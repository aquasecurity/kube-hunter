import os
import json
import logging
import socket
import sys
import time

import requests
from netaddr import IPNetwork, IPAddress

from __main__ import config
from netifaces import AF_INET, ifaddresses, interfaces, gateways

from ...core.events import handler
from ...core.events.types import Event, NewHostEvent, Vulnerability
from ...core.types import Discovery, InformationDisclosure, Azure, CloudTypes

class RunningPodOnCloud(Event):
    def __init__(self, cloud):
        self.cloud = cloud

class HostScanEvent(Event):
    pass

class RunningAsPodEvent(Event):
    def __init__(self):
        self.name = 'Running from within a pod'
        self.auth_token = self.get_service_account_file("token")
        self.client_cert = self.get_service_account_file("ca.crt")
        self.namespace = self.get_service_account_file("namespace")
        self.kubeservicehost = os.environ.get("KUBERNETES_SERVICE_HOST", None)

    # Event's logical location to be used mainly for reports.
    def location(self):
        location = "Local to Pod"
        if 'HOSTNAME' in os.environ:
            location += "(" + os.environ['HOSTNAME'] + ")"
        return location

    def get_service_account_file(self, file):
        try:
            with open("/var/run/secrets/kubernetes.io/serviceaccount/{file}".format(file=file)) as f:
                return f.read()
        except IOError:
            pass


class HostDiscoveryUtils:
    """ Static class containes util functions for Host discovery processes """
    @staticmethod
    def get_cloud(host):
        """ Returns cloud for a given ip address, defaults to NO_CLOUD """
        cloud = ""
        try:
            if host:
                logging.debug("Checking if {} is deployed on a cloud".format(host))
                # azurespeed.com provide their API via HTTP only; the service can be queried with 
                # HTTPS, but doesn't show a proper certificate. Since no encryption is worse then
                # any encryption, we go with the verify=false option for the time being. At least
                # this prevents leaking internal IP addresses to passive eavesdropping.
                # TODO: find a more secure service to detect cloud IPs
                metadata = requests.get("https://www.azurespeed.com/api/region?ipOrUrl={ip}".format(ip=host), verify=False).text
                if "cloud" in metadata:
                    cloud = json.loads(metadata)["cloud"]
        except requests.ConnectionError as e:
            logging.info("- unable to check cloud: {0}".format(e))

        return CloudTypes.get_enum(cloud)

    @staticmethod 
    def get_default_gateway():
        return gateways()['default'][AF_INET][0]

    @staticmethod
    def get_external_ip():
        external_ip = None
        try:
            logging.debug("HostDiscovery hunter attempting to get external IP address")
            external_ip = requests.get("https://canhazip.com", verify=False).text # getting external ip, to determine if cloud cluster
        except requests.ConnectionError as e:
            logging.debug("unable to determine external IP address: {0}".format(e))
        return external_ip

    # generator, generating ip addresses from a given cidr
    @staticmethod
    def generate_subnet(ip, sn="24"):
        logging.debug("HostDiscoveryUtils.generate_subnet {0}/{1}".format(ip, sn))
        return IPNetwork('{ip}/{sn}'.format(ip=ip, sn=sn))

    # generate ip addresses from all internal network interfaces
    @staticmethod
    def generate_interfaces_subnet(sn='24'):
        for ifaceName in interfaces():
            for ip in [i['addr'] for i in ifaddresses(ifaceName).setdefault(AF_INET, [])]:
                for ip in HostDiscoveryUtils.generate_subnet(ip, sn):
                    yield ip


@handler.subscribe(RunningAsPodEvent)
class FromPodHostDiscovery(Discovery):
    """Host Discovery when running as pod
    Generates ip adresses to scan, based on cluster/scan type
    """
    def __init__(self, event):
        self.event = event

    def execute(self):
        # If user has specified specific remotes, scanning only them
        if config.remote or config.cidr:
            self.publish_event(HostScanEvent())
        else:
            # figuring out the cloud from the external ip, default to CloudTypes.NO_CLOUD
            external_ip = HostDiscoveryUtils.get_external_ip()
            cloud = HostDiscoveryUtils.get_cloud(external_ip)

            # specific cloud discoveries should subscribe to RunningPodOnCloud
            if cloud != CloudTypes.NO_CLOUD:
                self.publish_event(RunningPodOnCloud(cloud=cloud))

            # normal pod discovery
            pod_subnet = self.pod_subnet_discovery()
            logging.debug("From pod scanning subnet {0}/{1}".format(pod_subnet[0], pod_subnet[1]))
            for ip in HostDiscoveryUtils.generate_subnet(ip=pod_subnet[0], sn=pod_subnet[1]):
                self.publish_event(NewHostEvent(host=ip, cloud=cloud))

            # manually publishing the Api server host if outside the subnet
            if self.event.kubeservicehost:
                if self.event.kubeservicehost not in IPNetwork("{}/{}".format(pod_subnet[0], pod_subnet[1])):
                    self.publish_event(NewHostEvent(host=IPAddress(self.event.kubeservicehost), cloud=cloud))


    def pod_subnet_discovery(self):
        # normal option when running as a pod is to scan it's own subnet
        # The gateway connects us to the host, and we can discover the 
        # kubelet from there, other ip's are pods that are running 
        # next to us,
        return HostDiscoveryUtils.get_default_gateway(), "24"


@handler.subscribe(HostScanEvent)
class HostDiscovery(Discovery):
    """Host Discovery
    Generates ip adresses to scan, based on cluster/scan type
    """
    def __init__(self, event):
        self.event = event

    def execute(self):
        # handling multiple scan options
        if config.cidr:
            try:
                ip, sn = config.cidr.split('/')
            except ValueError as e:
                logging.error("unable to parse cidr: {0}".format(e))
                return
            cloud = HostDiscoveryUtils.get_cloud(ip)
            for ip in HostDiscoveryUtils.generate_subnet(ip, sn=sn):
                self.publish_event(NewHostEvent(host=ip, cloud=cloud))                
        if config.internal:
            self.scan_interfaces()
        if len(config.remote) > 0:
            for host in config.remote:
                self.publish_event(NewHostEvent(host=host, cloud=HostDiscoveryUtils.get_cloud(host)))
 
    # for normal scanning
    def scan_interfaces(self):
        external_ip = HostDiscoveryUtils.get_external_ip()
        cloud = HostDiscoveryUtils.get_cloud(host=external_ip)
        for ip in HostDiscoveryUtils.generate_interfaces_subnet():
            handler.publish_event(NewHostEvent(host=ip, cloud=cloud))
