import logging

from ...core.events import handler
from ...core.events.types import Event, Vulnerability
from ...core.types import ActiveHunter, KubernetesCluster, IdentityTheft

from .arp import PossibleArpSpoofing

from scapy.all import *

class PossibleDnsSpoofing(Vulnerability, Event):
    """A malicous pod running on the cluster could potentially run a DNS Spoof attack and perform a MITM between pods on the node."""
    def __init__(self, kubedns_pod_ip):
        Vulnerability.__init__(self, KubernetesCluster, "Possible DNS Spoof", category=IdentityTheft)
        self.kubedns_pod_ip = kubedns_pod_ip
        self.evidence = "kube-dns at: {}".format(self.kubedns_pod_ip)

# Only triggered with RunningAsPod base event
@handler.subscribe(PossibleArpSpoofing)
class DnsSpoofHunter(ActiveHunter):
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