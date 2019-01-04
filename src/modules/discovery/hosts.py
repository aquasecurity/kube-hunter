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
from netifaces import AF_INET, ifaddresses, interfaces

from ...core.events import handler
from ...core.events.types import Event, NewHostEvent, Vulnerability
from ...core.types import Hunter, InformationDisclosure, Azure

class RunningAsPodEvent(Event):
    def __init__(self):
        self.name = 'Running from within a pod'
        self.auth_token = self.get_auth_token()
        self.client_cert = self.get_client_cert()
        
    def get_auth_token(self):
        try:
            with open("/run/secrets/kubernetes.io/serviceaccount/token") as token_file:
                return token_file.read()
        except IOError:
            pass
    def get_client_cert(self):
        return "/run/secrets/kubernetes.io/serviceaccount/ca.crt" 

class AzureMetadataApi(Vulnerability, Event):
    """Access to the Azure Metadata API exposes sensitive information about the machines associated with the cluster"""
    def __init__(self, cidr):
        Vulnerability.__init__(self, Azure, "Azure Metadata Exposure", category=InformationDisclosure)
        self.cidr = cidr
        self.evidence = "cidr: {}".format(cidr)

class HostScanEvent(Event):
    def __init__(self, pod=False, active=False, predefined_hosts=list()):
        self.active = active # flag to specify whether to get actual data from vulnerabilities
        self.predefined_hosts = predefined_hosts

class HostDiscoveryHelpers:
    @staticmethod
    def get_cloud(host):
        try:
            logging.debug("Passive hunter is checking whether the cluster is deployed on azure's cloud")
            metadata = requests.get("http://www.azurespeed.com/api/region?ipOrUrl={ip}".format(ip=host)).text
        except requests.ConnectionError as e:
            logging.info("- unable to check cloud: {0}".format(e))
            return
        if "cloud" in metadata:
            return json.loads(metadata)["cloud"]

    # generator, generating a subnet by given a cidr
    @staticmethod
    def generate_subnet(ip, sn="24"):
        logging.debug("HostDiscoveryHelpers.generate_subnet {0}/{1}".format(ip, sn))
        subnet = IPNetwork('{ip}/{sn}'.format(ip=ip, sn=sn))
        for ip in IPNetwork(subnet):
            logging.debug("HostDiscoveryHelpers.generate_subnet yielding {0}".format(ip))
            yield ip


@handler.subscribe(RunningAsPodEvent)
class FromPodHostDiscovery(Hunter):
    """Host Discovery when running as pod
    Generates ip adresses to scan, based on cluster/scan type
    """
    def __init__(self, event):
        self.event = event

    def execute(self):
        # Discover master API server from in-pod environment variable.

        if self.is_azure_pod():
            subnets, cloud =self.azure_metadata_discovery()
        else:
            subnets, cloud = self.traceroute_discovery()


        for subnet in subnets:
            logging.debug("From pod scanning subnet {0}/{1}".format(subnet[0], subnet[1]))
            for ip in HostDiscoveryHelpers.generate_subnet(ip=subnet[0], sn=subnet[1]):
                self.publish_event(NewHostEvent(host=ip, cloud=cloud))
            
    def is_azure_pod(self):
        try:
            logging.debug("Attempting to access Azure Metadata API")
            if requests.get("http://169.254.169.254/metadata/instance?api-version=2017-08-01", headers={"Metadata":"true"}, timeout=5).status_code == 200:
                return True
        except requests.exceptions.ConnectionError:
            return False

   # for pod scanning
    def traceroute_discovery(self):
        external_ip = requests.get("http://canhazip.com").text # getting external ip, to determine if cloud cluster
        cloud = HostDiscoveryHelpers.get_cloud(external_ip)
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR) # disables scapy's warnings
        from scapy.all import ICMP, IP, Ether, srp1

        node_internal_ip = srp1(Ether() / IP(dst="google.com" , ttl=1) / ICMP(), verbose=0)[IP].src
        return [ [node_internal_ip,"24"], ], external_ip

    # quering azure's interface metadata api | works only from a pod
    def azure_metadata_discovery(self):
        logging.debug("Passive hunter is attempting to pull azure's metadata")
        machine_metadata = json.loads(requests.get("http://169.254.169.254/metadata/instance?api-version=2017-08-01", headers={"Metadata":"true"}).text)
        address, subnet= "", ""
        subnets = list()
        for interface in machine_metadata["network"]["interface"]:
            address, subnet = interface["ipv4"]["subnet"][0]["address"], interface["ipv4"]["subnet"][0]["prefix"]
            logging.debug("From pod discovered subnet {0}/{1}".format(address, subnet if not config.quick else "24"))
            subnets.append([address,subnet if not config.quick else "24"])

        self.publish_event(AzureMetadataApi(cidr="{}/{}".format(address, subnet)))

        return subnets, "Azure"

@handler.subscribe(HostScanEvent)
class HostDiscovery(Hunter):
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
            cloud = HostDiscoveryHelpers.get_cloud(ip)
            for ip in HostDiscoveryHelpers.generate_subnet(ip, sn=sn):
                self.publish_event(NewHostEvent(host=ip, cloud=cloud))                
        elif config.internal:
            self.scan_interfaces()
        elif len(config.remote) > 0:
            for host in config.remote:
                self.publish_event(NewHostEvent(host=host, cloud=HostDiscoveryHelpers.get_cloud(host)))
 
    # for normal scanning
    def scan_interfaces(self):
        try:
            logging.debug("Passive hunter is attempting to get external IP address")
            external_ip = requests.get("http://canhazip.com").text # getting external ip, to determine if cloud cluster
        except requests.ConnectionError as e:
            logging.debug("unable to determine local IP address: {0}".format(e))
            logging.info("~ default to 127.0.0.1")
            external_ip = "127.0.0.1"
        cloud = HostDiscoveryHelpers.get_cloud(external_ip)
        for ip in self.generate_interfaces_subnet():
            handler.publish_event(NewHostEvent(host=ip, cloud=cloud))

    # generate all subnets from all internal network interfaces
    def generate_interfaces_subnet(self, sn='24'):
        for ifaceName in interfaces():
            for ip in [i['addr'] for i in ifaddresses(ifaceName).setdefault(AF_INET, [])]:
                if not self.event.localhost and InterfaceTypes.LOCALHOST.value in ip.__str__():
                    continue
                for ip in HostDiscoveryHelpers.generate_subnet(ip, sn):
                    yield ip
                    
# for comparing prefixes
class InterfaceTypes(Enum):
    LOCALHOST = "127"
