import logging

from ...core.events import handler
from ...core.events.types import Event, Vulnerability
from ...core.types import ActiveHunter, KubernetesCluster, IdentityTheft

from .capabilities import CapNetRawEnabled 

from scapy.all import ARP, IP, ICMP, Ether, sr1, srp

class PossibleArpSpoofing(Vulnerability, Event):
    """A malicious pod running on the cluster could potentially run an ARP Spoof attack and perform a MITM between pods on the node."""
    def __init__(self):
        Vulnerability.__init__(self, KubernetesCluster, "Possible Arp Spoof", category=IdentityTheft,vid="KHV020")

@handler.subscribe(CapNetRawEnabled)
class ArpSpoofHunter(ActiveHunter):
    """Arp Spoof Hunter
    Checks for the possibility of running an ARP spoof attack from within a pod (results are based on the running node)
    """
    def __init__(self, event):
        self.event = event

    def try_getting_mac(self, ip):
        ans = sr1(ARP(op=1, pdst=ip),timeout=2, verbose=0)  
        return ans[ARP].hwsrc if ans else None

    def detect_l3_on_host(self, arp_responses):
        """ returns True for an existance of an L3 network plugin """
        logging.debug("Attempting to detect L3 network plugin using ARP")
        unique_macs = list(set(response[ARP].hwsrc for _, response in arp_responses))
        
        # if LAN addresses not unique
        if len(unique_macs) == 1:
            # if an ip outside the subnets gets a mac address
            outside_mac = self.try_getting_mac("1.1.1.1")
            # outside mac is the same as lan macs
            if outside_mac == unique_macs[0]:
                return True
        # only one mac address for whole LAN and outside 
        return False
        
    def execute(self):
        self_ip = sr1(IP(dst="1.1.1.1", ttl=1), ICMP(), verbose=0)[IP].dst 
        arp_responses, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst="{}/24".format(self_ip)), timeout=3, verbose=0)
        
        # arp enabled on cluster and more than one pod on node
        if len(arp_responses) > 1:
            # L3 plugin not installed
            if not self.detect_l3_on_host(arp_responses):
                self.publish_event(PossibleArpSpoofing())
