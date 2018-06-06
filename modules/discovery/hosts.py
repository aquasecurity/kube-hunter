import logging
import sys
import time
from enum import Enum

import requests
from netaddr import IPNetwork
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) # disables scapy's warnings
from scapy.all import ICMP, IP, Ether, srp1

from netifaces import AF_INET, ifaddresses, interfaces

from ..events import handler
from ..events.types import HostScanEvent, NewHostEvent
from ..types import Hunter

# for comparing prefixes
class InterfaceTypes(Enum):
    LOCALHOST = "127"

@handler.subscribe(HostScanEvent)
class HostDiscovery(Hunter):
    def __init__(self, event):
        self.event = event

    def execute(self):
        logging.info("Discovering Open Kubernetes Services...")
        if self.event.pod:
            self.scan_nodes()
        else:
            # self.publish_event(NewHostEvent(host="acs954agent1.westus2.cloudapp.azure.com")) # test cluster
            self.scan_interfaces()

    # for pod scanning
    def scan_nodes(self):
        node_internal_ip = srp1(Ether() / IP(dst="google.com" , ttl=1) / ICMP(), verbose=0)[IP].src
        for ip in self.generate_subnet(ip=node_internal_ip, sn="24"):
            self.publish_event(NewHostEvent(host=ip))

    # for normal scanning
    def scan_interfaces(self):
        for ip in self.generate_interfaces_subnet():
            handler.publish_event(NewHostEvent(host=ip))

    # generate all subnets from all internal network interfaces
    def generate_interfaces_subnet(self, sn='24'):
        for ifaceName in interfaces():
            for ip in [i['addr'] for i in ifaddresses(ifaceName).setdefault(AF_INET, [])]:
                if not self.event.localhost and InterfaceTypes.LOCALHOST.value in ip.__str__():
                    continue
                for ip in self.generate_subnet(ip, sn):
                    yield ip

    # generator, generating a subnet by given a cidr
    def generate_subnet(self, ip, sn="24"):
        subnet = IPNetwork('{ip}/{sn}'.format(ip=ip, sn=sn))
        for ip in IPNetwork(subnet):
            yield ip