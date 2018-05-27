import logging
import sys
import time
from enum import Enum
from ..types import Hunter

from netaddr import IPNetwork

from ..events import handler
from ..events.types import HostScanEvent, NewHostEvent
from netifaces import AF_INET, ifaddresses, interfaces


# for comparing prefixes
class InterfaceTypes(Enum):
    LOCALHOST = "127.0.0"

@handler.subscribe(HostScanEvent)
class HostDiscovery(Hunter):
    def __init__(self, event):
        self.event = event
        # self.external = event.external

    def execute(self):
        logging.info("Discovering Open Kubernetes Services...")
        
        self.publish_event(NewHostEvent(host="acs954agent1.westus2.cloudapp.azure.com")) # test cluster
        # for ifaceName in interfaces():
        #     for ip in self.generate_addresses(ifaceName):
        #         handler.publish_event(NewHostEvent(host=ip))

    def generate_addresses(self, ifaceName):
        for address in [i['addr'] for i in ifaddresses(ifaceName).setdefault(AF_INET, [])]:
            subnet = IPNetwork('{0}/24'.format(address))
            for ip in IPNetwork(subnet):
                if not self.event.localhost and InterfaceTypes.LOCALHOST.value in ip.__str__():
                    continue
                yield ip