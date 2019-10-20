import logging
import json
from ...core.types import Hunter, RemoteCodeExec, KubernetesCluster

import requests

from ...core.events import handler
from ...core.events.types import Vulnerability, Event
from ..discovery.dashboard import KubeDashboardEvent

class DashboardExposed(Vulnerability, Event):
    """All operations on the cluster are exposed"""
    def __init__(self, nodes):
        Vulnerability.__init__(self, KubernetesCluster, "Dashboard Exposed", category=RemoteCodeExec, vid="KHV029")
        self.evidence = "nodes: {}".format(' '.join(nodes)) if nodes else None

@handler.subscribe(KubeDashboardEvent)
class KubeDashboard(Hunter):
    """Dashboard Hunting
    Hunts open Dashboards, gets the type of nodes in the cluster
    """
    def __init__(self, event):
        self.event = event

    def get_nodes(self):
        logging.debug("Passive hunter is attempting to get nodes types of the cluster")
        r = requests.get("http://{}:{}/api/v1/node".format(self.event.host, self.event.port))
        if r.status_code == 200 and "nodes" in r.text:
            return list(map(lambda node: node["objectMeta"]["name"], json.loads(r.text)["nodes"]))
        
    def execute(self):
        self.publish_event(DashboardExposed(nodes=self.get_nodes()))        