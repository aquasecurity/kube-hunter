import os
import json
import logging
import socket
import sys
import time
from enum import Enum

import requests
from netaddr import IPNetwork

from __main__ import config
from netifaces import AF_INET, ifaddresses, interfaces, gateways

from ...core.events import handler
from ...core.events.types import Event, NewHostEvent, Vulnerability
from ...core.types import Discovery, InformationDisclosure, Azure

class RunningAsPodEvent(Event):
    def __init__(self):
        self.name = 'Running from within a pod'
        self.auth_token = self.get_service_account_file("token")
        self.client_cert = self.get_service_account_file("ca.crt")
        self.namespace = self.get_service_account_file("namespace")

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

class AzureMetadataApi(Vulnerability, Event):
    """Access to the Azure Metadata API exposes information about the machines associated with the cluster"""
    def __init__(self, cidr):
        Vulnerability.__init__(self, Azure, "Azure Metadata Exposure", category=InformationDisclosure)
        self.cidr = cidr
        self.evidence = "cidr: {}".format(cidr)

class HostScanEvent(Event):
    def __init__(self, pod=False, active=False, predefined_hosts=list()):
        self.active = active # flag to specify whether to get actual data from vulnerabilities
        self.predefined_hosts = predefined_hosts


# for comparing prefixes
class InterfaceTypes(Enum):
    LOCALHOST = "127"

class CloudTypes(Enum):
    AZURE = "Azure"


class HostDiscoveryUtils:
    """ Static class containes util functions for Host discovery processes """
    @classmethod
    def get_cloud(cls, host=None):
        """ Returns cloud for a given ip address, defaults to the external ip"""
        if not host:
            host = cls._get_external_ip()
        try:
            if host:
                logging.debug("Checking whether the cluster is deployed on azure's cloud")
                # azurespeed.com provide their API via HTTP only; the service can be queried with 
                # HTTPS, but doesn't show a proper certificate. Since no encryption is worse then
                # any encryption, we go with the verify=false option for the time being. At least
                # this prevents leaking internal IP addresses to passive eavesdropping.
                # TODO: find a more secure service to detect cloud IPs
                metadata = requests.get("https://www.azurespeed.com/api/region?ipOrUrl={ip}".format(ip=host), verify=False).text
        except requests.ConnectionError as e:
            logging.info("- unable to check cloud: {0}".format(e))
            return
        if "cloud" in metadata:
            return json.loads(metadata)["cloud"]

    @staticmethod 
    def get_default_gateway():
        return gateways()['default'][AF_INET][0]

    @staticmethod
    def _get_external_ip():
        external_ip = None
        try:
            logging.debug("HostDiscovery hunter attempting to get external IP address")
            external_ip = requests.get("http://canhazip.com").text # getting external ip, to determine if cloud cluster
        except requests.ConnectionError as e:
            logging.debug("unable to determine external IP address: {0}".format(e))
        return external_ip

    # generator, generating ip addresses from a given cidr
    @staticmethod
    def generate_subnet(ip, sn="24"):
        logging.debug("HostDiscoveryUtils.generate_subnet {0}/{1}".format(ip, sn))
        subnet = IPNetwork('{ip}/{sn}'.format(ip=ip, sn=sn))
        for ip in IPNetwork(subnet):
            logging.debug("HostDiscoveryUtils.generate_subnet yielding {0}".format(ip))
            yield ip

    # generate ip addresses from all internal network interfaces
    @staticmethod
    def generate_interfaces_subnet(sn='24'):
        for ifaceName in interfaces():
            for ip in [i['addr'] for i in ifaddresses(ifaceName).setdefault(AF_INET, [])]:
                if InterfaceTypes.LOCALHOST.value in ip.__str__():
                    continue
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
        scan_subnets = list()
        # Scan any hosts that the user specified
        if config.remote or config.cidr:
            self.publish_event(HostScanEvent())
        else:
            # TODO: add more api discoveries
            # If we have access to azure's api, we extract subnets from there 
            if self.is_azure_api():
                subnets, cloud = self.azure_metadata_discovery()
                scan_subnets += subnets

            subnets, cloud = self.pod_discovery()
            scan_subnets += subnets

            for subnet in scan_subnets:
                logging.debug("From pod scanning subnet {0}/{1}".format(subnet[0], subnet[1]))
                for ip in HostDiscoveryUtils.generate_subnet(ip=subnet[0], sn=subnet[1]):
                    self.publish_event(NewHostEvent(host=ip, cloud=cloud))
    
    def is_azure_api(self):
        try:
            logging.debug("From pod attempting to access Azure Metadata API")
            if requests.get("http://169.254.169.254/metadata/instance?api-version=2017-08-01", headers={"Metadata":"true"}, timeout=5).status_code == 200:
                return True
        except requests.exceptions.ConnectionError:
            return False

    def pod_discovery(self):
        # normal option when running as a pod is to scan it's own subnet
        # The gateway connects us to the host, and we can discover the 
        # kubelet from there, other ip's are pods that are running 
        # next to us
        return [(HostDiscoveryUtils.get_default_gateway(), "24")], HostDiscoveryUtils.get_cloud()
        
    # quering azure's interface metadata api | works only from a pod
    def azure_metadata_discovery(self):
        logging.debug("From pod attempting to access azure's metadata")
        machine_metadata = json.loads(requests.get("http://169.254.169.254/metadata/instance?api-version=2017-08-01", headers={"Metadata":"true"}).text)
        subnets = list()
        for interface in machine_metadata["network"]["interface"]:
            address, subnet = interface["ipv4"]["subnet"][0]["address"], interface["ipv4"]["subnet"][0]["prefix"]
            logging.debug("From pod discovered subnet {0}/{1}".format(address, subnet if not config.quick else "24"))
            subnets.append([address,subnet if not config.quick else "24"])
            self.publish_event(AzureMetadataApi(cidr="{}/{}".format(address, subnet)))

        return subnets, CloudTypes.AZURE.value

@handler.subscribe(HostScanEvent)
class HostDiscovery(Discovery):
    """Host Discovery
    Generates ip adresses to scan, based on cluster/scan type
    """
    def __init__(self, event):
        self.event = event

    def execute(self):
        if config.cidr:
            try:
                ip, sn = config.cidr.split('/')
            except ValueError as e:
                logging.error("unable to parse cidr: {0}".format(e))
                return
            cloud = HostDiscoveryUtils.get_cloud(ip)
            for ip in HostDiscoveryUtils.generate_subnet(ip, sn=sn):
                self.publish_event(NewHostEvent(host=ip, cloud=cloud))                
        elif config.internal:
            self.scan_interfaces()
        elif len(config.remote) > 0:
            for host in config.remote:
                self.publish_event(NewHostEvent(host=host, cloud=HostDiscoveryUtils.get_cloud(host)))
 
    # for normal scanning
    def scan_interfaces(self):
        cloud = HostDiscoveryUtils.get_cloud()
        for ip in HostDiscoveryUtils.generate_interfaces_subnet():
            handler.publish_event(NewHostEvent(host=ip, cloud=cloud))
