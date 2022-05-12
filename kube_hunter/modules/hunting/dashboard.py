import logging
import json
import requests

from kube_hunter.conf import get_config
from kube_hunter.core.types import Hunter, AccessK8sDashboardTechnique, KubernetesCluster
from kube_hunter.core.events.event_handler import handler
from kube_hunter.core.events.types import Vulnerability, Event
from kube_hunter.modules.discovery.dashboard import KubeDashboardEvent

logger = logging.getLogger(__name__)


class DashboardExposed(Vulnerability, Event):
    """All operations on the cluster are exposed"""

    def __init__(self, nodes):
        Vulnerability.__init__(
            self,
            KubernetesCluster,
            "Dashboard Exposed",
            category=AccessK8sDashboardTechnique,
            vid="KHV029",
        )
        self.evidence = "nodes: {}".format(" ".join(nodes)) if nodes else None


@handler.subscribe(KubeDashboardEvent)
class KubeDashboard(Hunter):
    """Dashboard Hunting
    Hunts open Dashboards, gets the type of nodes in the cluster
    """

    def __init__(self, event):
        self.event = event

    def get_nodes(self):
        config = get_config()
        logger.debug("Passive hunter is attempting to get nodes types of the cluster")
        r = requests.get(f"http://{self.event.host}:{self.event.port}/api/v1/node", timeout=config.network_timeout)
        if r.status_code == 200 and "nodes" in r.text:
            return [node["objectMeta"]["name"] for node in json.loads(r.text)["nodes"]]

    def execute(self):
        self.publish_event(DashboardExposed(nodes=self.get_nodes()))
