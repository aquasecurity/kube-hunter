import logging

from scapy.all import ARP, IP, ICMP, Ether, sr1, srp

from kube_hunter.conf import get_config
from kube_hunter.core.events import handler
from kube_hunter.core.events.types import Event, Vulnerability
from kube_hunter.core.types import ActiveHunter, KubernetesCluster, IdentityTheft
from kube_hunter.modules.hunting.capabilities import CapNetRawEnabled

logger = logging.getLogger(__name__)


class PossibleArpSpoofing(Vulnerability, Event):
    """A malicious pod running on the cluster could potentially run an ARP Spoof attack
    and perform a MITM between pods on the node."""

    def __init__(self):
        Vulnerability.__init__(
            self,
            KubernetesCluster,
            "Possible Arp Spoof",
            category=IdentityTheft,
            vid="KHV020",
        )


@handler.subscribe(CapNetRawEnabled)
class ArpSpoofHunter(ActiveHunter):
    """Arp Spoof Hunter
    Checks for the possibility of running an ARP spoof
    attack from within a pod (results are based on the running node)
    """

    def __init__(self, event):
        self.event = event

    def try_getting_mac(self, ip):
        config = get_config()
        ans = sr1(ARP(op=1, pdst=ip), timeout=config.network_timeout, verbose=0)
        return ans[ARP].hwsrc if ans else None

    def detect_l3_on_host(self, arp_responses):
        """returns True for an existence of an L3 network plugin"""
        logger.debug("Attempting to detect L3 network plugin using ARP")
        unique_macs = list({response[ARP].hwsrc for _, response in arp_responses})

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
        config = get_config()
        self_ip = sr1(IP(dst="1.1.1.1", ttl=1) / ICMP(), verbose=0, timeout=config.network_timeout)[IP].dst
        arp_responses, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=f"{self_ip}/24"),
            timeout=config.network_timeout,
            verbose=0,
        )

        # arp enabled on cluster and more than one pod on node
        if len(arp_responses) > 1:
            # L3 plugin not installed
            if not self.detect_l3_on_host(arp_responses):
                self.publish_event(PossibleArpSpoofing())
