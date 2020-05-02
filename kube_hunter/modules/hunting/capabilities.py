import socket
import logging

from kube_hunter.modules.discovery.hosts import RunningAsPodEvent
from kube_hunter.core.pubsub.subscription import subscribe
from kube_hunter.core.types import AccessRisk, Hunter, KubernetesCluster, Vulnerability

logger = logging.getLogger(__name__)


class CapNetRawEnabled(Vulnerability):
    """CAP_NET_RAW is enabled by default for pods.
    If an attacker manages to compromise a pod,
    he can potentially take advantage of this capability to perform network
    attacks on other pods running on the same node"""

    def __init__(self):
        super().__init__(name="CAP_NET_RAW Enabled", component=KubernetesCluster, category=AccessRisk)


@subscribe(RunningAsPodEvent)
class PodCapabilitiesHunter(Hunter):
    """Pod Capabilities Hunter
    Checks for default enabled capabilities in a pod
    """

    def check_net_raw(self):
        logger.debug("Trying to open a raw socket")
        try:
            # CAP_NET_RAW is mandatory for opening a raw socket
            socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW).close()
        except PermissionError:
            logger.debug("Failed to open raw socket")
            return False
        else:
            return True

    def execute(self):
        if self.check_net_raw():
            yield CapNetRawEnabled()
