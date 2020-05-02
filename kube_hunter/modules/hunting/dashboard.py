import logging
import requests

from kube_hunter.conf import get_config
from kube_hunter.core.pubsub.subscription import subscribe
from kube_hunter.core.types import Hunter, KubernetesCluster, RemoteCodeExec, Vulnerability
from kube_hunter.modules.discovery.dashboard import KubeDashboardEvent

logger = logging.getLogger(__name__)


class DashboardExposed(Vulnerability):
    """All operations on the cluster are exposed"""

    def __init__(self, nodes):
        super().__init__(
            name="Dashboard Exposed",
            component=KubernetesCluster,
            category=RemoteCodeExec,
            vid="KHV029",
            evidence=f"nodes: {', '.join(nodes)}" if nodes else "",
        )


@subscribe(KubeDashboardEvent)
class KubeDashboard(Hunter):
    """Dashboard Hunting
    Hunts open kubernets dashboard, gets the type of nodes in the cluster
    """

    def get_nodes(self):
        config = get_config()
        logger.debug("Trying to get type of cluster nodes")
        try:
            endpoint = f"http://{self.event.host}:{self.event.port}/api/v1/node"
            nodes = requests.get(endpoint, timeout=config.network_timeout).json()["nodes"]
        except Exception:
            logging.debug(f"Failed to get nodes from {endpoint}", exc_info=True)
            return []
        else:
            return [node["objectMeta"]["name"] for node in nodes]

    def execute(self):
        nodes = self.get_nodes()
        if nodes:
            yield DashboardExposed(nodes)
