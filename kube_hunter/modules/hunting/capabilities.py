import socket
import logging

from kube_hunter.modules.discovery.hosts import RunningAsPodEvent
from kube_hunter.core.events import handler
from kube_hunter.core.events.types import Event, Vulnerability
from kube_hunter.core.types import Hunter, AccessRisk, KubernetesCluster

logger = logging.getLogger(__name__)


class CapNetRawEnabled(Event, Vulnerability):
    """CAP_NET_RAW is enabled by default for pods.
    If an attacker manages to compromise a pod,
    they could potentially take advantage of this capability to perform network
    attacks on other pods running on the same node"""

    def __init__(self):
        Vulnerability.__init__(
            self,
            KubernetesCluster,
            name="CAP_NET_RAW Enabled",
            category=AccessRisk,
        )


@handler.subscribe(RunningAsPodEvent)
class PodCapabilitiesHunter(Hunter):
    """Pod Capabilities Hunter
    Checks for default enabled capabilities in a pod
    """

    def __init__(self, event):
        self.event = event

    def check_net_raw(self):
        logger.debug("Passive hunter's trying to open a RAW socket")
        try:
            # trying to open a raw socket without CAP_NET_RAW will raise PermissionsError
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            s.close()
            logger.debug("Passive hunter's closing RAW socket")
            return True
        except PermissionError:
            logger.debug("CAP_NET_RAW not enabled")

    def execute(self):
        if self.check_net_raw():
            self.publish_event(CapNetRawEnabled())
