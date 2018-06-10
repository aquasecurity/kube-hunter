import logging
import sys
import time
import json
from enum import Enum

import requests
from netaddr import IPNetwork
from netifaces import AF_INET, ifaddresses, interfaces

from ..events import handler
from ..events.types import Event, NewHostEvent
from ..types import Hunter

class HostScanEvent(Event):
    def __init__(self, pod=False, active=False):
        self.pod = pod
        self.active = active # flag to specify whether to get actual data from vulnerabilities
        self.auth_token = self.get_auth_token()
        self.client_cert = self.get_client_cert()

    def get_auth_token(self):
        if self.pod:
            with open("/run/secrets/kubernetes.io/serviceaccount/token") as token_file:
                return token_file.read()
        return None

    def get_client_cert(self):
        if self.pod:
            return "/run/secrets/kubernetes.io/serviceaccount/ca.crt" 
        return None

@handler.subscribe(HostScanEvent)
class HostDiscovery(Hunter):
    def __init__(self, event):
        self.event = event

    def execute(self):
        logging.info("Discovering Open Kubernetes Services...")
        if self.event.pod:
            if self.is_azure_cluster():
                self.azure_metadata_discovery()
            else:
                self.traceroute_discovery()
        else:
            # self.publish_event(NewHostEvent(host="acs954agent1.westus2.cloudapp.azure.com")) # test cluster
            self.scan_interfaces()

    def is_azure_cluster(self):
        try:
            if requests.get("http://169.254.169.254/metadata/instance?api-version=2017-08-01", headers={"Metadata":"true"}).status_code == 200:
                return True
        except Exception as ex:
            logging.debug("Not azure cluster " + ex.message)
        return False

    # for pod scanning
    def traceroute_discovery(self):
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR) # disables scapy's warnings
        from scapy.all import ICMP, IP, Ether, srp1

        node_internal_ip = srp1(Ether() / IP(dst="google.com" , ttl=1) / ICMP(), verbose=0)[IP].src
        for ip in self.generate_subnet(ip=node_internal_ip, sn="24"):
            self.publish_event(NewHostEvent(host=ip))

    # quering azure's interface metadata api | works only from a pod
    def azure_metadata_discovery(self):
        machine_metadata = json.loads(requests.get("http://169.254.169.254/metadata/instance?api-version=2017-08-01", headers={"Metadata":"true"}).text)
        for interface in machine_metadata["network"]["interface"]:
            address, subnet = interface["ipv4"]["subnet"][0]["address"], interface["ipv4"]["subnet"][0]["prefix"]
            for ip in self.generate_subnet(address, sn=subnet):
                self.publish_event(NewHostEvent(host=ip))

    # for normal scanning
    def scan_interfaces(self):
        for ip in self.generate_interfaces_subnet():
            handler.publish_event(NewHostEvent(host=ip))

    # generator, generating a subnet by given a cidr
    def generate_subnet(self, ip, sn="24"):
        subnet = IPNetwork('{ip}/{sn}'.format(ip=ip, sn=sn))
        for ip in IPNetwork(subnet):
            yield ip

    # generate all subnets from all internal network interfaces
    def generate_interfaces_subnet(self, sn='24'):
        for ifaceName in interfaces():
            for ip in [i['addr'] for i in ifaddresses(ifaceName).setdefault(AF_INET, [])]:
                if not self.event.localhost and InterfaceTypes.LOCALHOST.value in ip.__str__():
                    continue
                for ip in self.generate_subnet(ip, sn):
                    yield ip
                    
# for comparing prefixes
class InterfaceTypes(Enum):
    LOCALHOST = "127"