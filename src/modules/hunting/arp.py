import json
import logging

from ...core.events import handler
from ...core.events.types import Event, Vulnerability
from ...core.types import Hunter, ActiveHunter, KubernetesCluster, IdentityTheft

from ..discovery.hosts import RunningAsPodEvent

from scapy.all import *

class PossibleArpSpoofing(Vulnerability, Event):
    """A malicous pod running on the cluster could potentially run an ARP Spoof attack and perform a MITM between pods on the node."""
    def __init__(self):
        Vulnerability.__init__(self, KubernetesCluster, "Possible Arp Spoof", category=IdentityTheft)

class PossibleDnsSpoofing(Vulnerability, Event):
    """A malicous pod running on the cluster could potentially run a DNS Spoof attack and perform a MITM between pods on the node."""
    def __init__(self, kubedns_pod_ip):
        Vulnerability.__init__(self, KubernetesCluster, "Possible DNS Spoof", category=IdentityTheft)
        self.kubedns_pod_ip = kubedns_pod_ip
        self.evidence = "kube-dns at: {}".format(self.kubedns_pod_ip)

@handler.subscribe(RunningAsPodEvent)
class ArpSpoofHunter(Hunter):
    def __init__(self, event):
        self.event = event

    def try_getting_mac(self, ip):
        ans = sr1(ARP(op=1, pdst=ip),timeout=2, verbose=0)  
        return ans[ARP].hwsrc if ans else None

    def detect_l3_on_host(self, arp_responses):
        """ returns True for an existance of an L3 network plugin """
        logging.debug("Attempting to detect L3 network plugin using ARP")
        unique_macs = list(set([a[1][ARP].hwsrc for a in arp_responses]))
        
        # if LAN addresses not unique
        if len(unique_macs) == 1:
            # if an ip outside the subnets gets a mac address
            outside_mac = try_getting_mac("8.8.8.8")
            if outside_mac:
                # outside mac is the same as lan macs
                if outside_mac == unique_macs[0]:
                    return True
        # only one mac address for whole LAN and outside 
        return False
        
    def execute(self):
        self_ip = sr1(IP(dst="google.com", ttl=1), ICMP(), verbose=0)[IP].dst 
        arp_responses, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst="{}/24".format(self_ip)), timeout=3, verbose=0)
        
        # arp enabled on cluster and more than one pod on node
        if len(arp_responses) > 1:
            # L3 plugin not installed
            if not self.detect_l3(arp_responses):
                self.publish_event(PossibleArpSpoofing())


# Only triggered with RunningAsPod base event
@handler.subscribe(PossibleArpSpoofing)
class DnsSpoofHunter(Hunter):
    def __init__(self, event):
        self.event = event
    
    def get_cbr0_ip_mac(self):
        res = srp1(Ether() / IP(dst="google.com" , ttl=1) / ICMP(), verbose=0)
        return res[IP].src, res.src

    def get_kube_dns_ip_mac(self):
        with open('/etc/resolv.conf', 'r') as f:
            kubedns_svc_ip = f.readlines()[0].split(' ')[1].strip()

        # getting actuall pod ip of kube-dns service, by comparing the src mac of a dns response and arp scanning.
        dns_info_res = srp1(Ether() / IP(dst=kubedns_svc_ip) / UDP(dport=53) / DNS(rd=1,qd=DNSQR()), verbose=0)
        kubedns_pod_mac = dns_info_res.src
        self_ip = dns_info_res[IP].dst

        arp_responses, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst="{}/24".format(self_ip)), timeout=3, verbose=0)
        for res in arp_responses:
            if res[1][Ether].src == kubedns_pod_mac:
                return res[1][ARP].psrc, res[1].src
    
    def execute(self):
        logging.debug("Attempting to get kube-dns pod ip")
        self_ip = sr1(IP(dst="google.com", ttl=1), ICMP(), verbose=0)[IP].dst 
        kubedns_ip, kubedns_mac = self.get_kube_dns_ip_mac()
        cbr0_ip, cbr0_mac = self.get_cbr0_ip_mac()

        logging.debug("ip = {}, kubednsip = {}, cbr0ip = {}".format(self_ip, kubedns_ip, cbr0_ip))
        if kubedns_mac != cbr0_mac:
            # if self pod in the same subnet as kube-dns pod
            self.publish_event(PossibleDnsSpoofing(kubedns_pod_ip=kubedns_ip))