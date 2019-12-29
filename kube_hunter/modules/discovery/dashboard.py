import json
import logging

import requests

from kube_hunter.core.events import handler
from kube_hunter.core.events.types import Event, OpenPortEvent, Service
from kube_hunter.core.types import Discovery


class KubeDashboardEvent(Service, Event):
    """A web-based Kubernetes user interface. allows easy usage with operations on the cluster"""
    def __init__(self, **kargs):
        Service.__init__(self, name="Kubernetes Dashboard", **kargs)

@handler.subscribe(OpenPortEvent, predicate=lambda x: x.port == 30000)
class KubeDashboard(Discovery):
    """K8s Dashboard Discovery
    Checks for the existence of a Dashboard
    """
    def __init__(self, event):
        self.event = event

    @property
    def secure(self):
        logging.debug("Attempting to discover an Api server to access dashboard")
        r = requests.get("http://{}:{}/api/v1/service/default".format(self.event.host, self.event.port))
        if "listMeta" in r.text and len(json.loads(r.text)["errors"]) == 0:
            return False
        return True

    def execute(self):
        if not self.secure:
            self.publish_event(KubeDashboardEvent())
