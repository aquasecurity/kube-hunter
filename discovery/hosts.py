from netifaces import interfaces, ifaddresses, AF_INET
from netaddr import IPNetwork
import events 


class HostDiscovery(object):
    def __init__(self, task):
        pass

    def execute(self):
        for ifaceName in interfaces():
            addresses = [i['addr'] for i in ifaddresses(ifaceName).setdefault(AF_INET, [])]
            if addresses:
                subnet = IPNetwork('{0}/24'.format(addresses[0]))
                for single_ip in IPNetwork(subnet):
                    events.handler.publish_event('NEW_HOST', {'host': single_ip})