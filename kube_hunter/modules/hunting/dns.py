import re
import logging

from scapy.all import IP, ICMP, UDP, DNS, DNSQR, ARP, Ether, sr1, srp1, srp

from kube_hunter.conf import get_config
from kube_hunter.core.events import handler
from kube_hunter.core.events.types import Event, Vulnerability
from kube_hunter.core.types import ActiveHunter, KubernetesCluster, IdentityTheft
from kube_hunter.modules.hunting.arp import PossibleArpSpoofing

logger = logging.getLogger(__name__)


class PossibleDnsSpoofing(Vulnerability, Event):
    """A malicious pod running on the cluster could potentially run a DNS Spoof attack
    and perform a MITM attack on applications running in the cluster."""

    def __init__(self, kubedns_pod_ip):
        Vulnerability.__init__(
            self,
            KubernetesCluster,
            "Possible DNS Spoof",
            category=IdentityTheft,
            vid="KHV030",
        )
        self.kubedns_pod_ip = kubedns_pod_ip
        self.evidence = f"kube-dns at: {self.kubedns_pod_ip}"


# Only triggered with RunningAsPod base event
@handler.subscribe(PossibleArpSpoofing)
class DnsSpoofHunter(ActiveHunter):
    """DNS Spoof Hunter
    Checks for the possibility for a malicious pod to compromise DNS requests of the cluster
    (results are based on the running node)
    """

    def __init__(self, event):
        self.event = event

    def get_cbr0_ip_mac(self):
        config = get_config()
        res = srp1(Ether() / IP(dst="1.1.1.1", ttl=1) / ICMP(), verbose=0, timeout=config.network_timeout)
        return res[IP].src, res.src

    def extract_nameserver_ip(self):
        with open("/etc/resolv.conf") as f:
            # finds first nameserver in /etc/resolv.conf
            match = re.search(r"nameserver (\d+.\d+.\d+.\d+)", f.read())
            if match:
                return match.group(1)

    def get_kube_dns_ip_mac(self):
        config = get_config()
        kubedns_svc_ip = self.extract_nameserver_ip()

        # getting actual pod ip of kube-dns service, by comparing the src mac of a dns response and arp scanning.
        dns_info_res = srp1(
            Ether() / IP(dst=kubedns_svc_ip) / UDP(dport=53) / DNS(rd=1, qd=DNSQR()),
            verbose=0,
            timeout=config.network_timeout,
        )
        kubedns_pod_mac = dns_info_res.src
        self_ip = dns_info_res[IP].dst

        arp_responses, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=f"{self_ip}/24"),
            timeout=config.network_timeout,
            verbose=0,
        )
        for _, response in arp_responses:
            if response[Ether].src == kubedns_pod_mac:
                return response[ARP].psrc, response.src

    def execute(self):
        config = get_config()
        logger.debug("Attempting to get kube-dns pod ip")
        self_ip = sr1(IP(dst="1.1.1.1", ttl=1) / ICMP(), verbose=0, timeout=config.network_timeout)[IP].dst
        cbr0_ip, cbr0_mac = self.get_cbr0_ip_mac()

        kubedns = self.get_kube_dns_ip_mac()
        if kubedns:
            kubedns_ip, kubedns_mac = kubedns
            logger.debug(f"ip={self_ip} kubednsip={kubedns_ip} cbr0ip={cbr0_ip}")
            if kubedns_mac != cbr0_mac:
                # if self pod in the same subnet as kube-dns pod
                self.publish_event(PossibleDnsSpoofing(kubedns_pod_ip=kubedns_ip))
        else:
            logger.debug("Could not get kubedns identity")
