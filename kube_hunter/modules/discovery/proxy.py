import logging
import requests

from collections import defaultdict
from requests import get

from kube_hunter.core.types import Discovery
from kube_hunter.core.events import handler
from kube_hunter.core.events.types import Service, Event, OpenPortEvent

class KubeProxyEvent(Event, Service):
    """proxies from a localhost address to the Kubernetes apiserver"""
    def __init__(self):
        Service.__init__(self, name="Kubernetes Proxy")

@handler.subscribe(OpenPortEvent, predicate=lambda x: x.port == 8001)
class KubeProxy(Discovery):
    """Proxy Discovery
    Checks for the existence of a an open Proxy service
    """
    def __init__(self, event):
        self.event = event
        self.host = event.host
        self.port = event.port or 8001

    @property
    def accesible(self):
        logging.debug("Attempting to discover a proxy service")
        r = requests.get("http://{host}:{port}/api/v1".format(host=self.host, port=self.port))
        if r.status_code == 200 and "APIResourceList" in r.text:
            return True

    def execute(self):
        if self.accesible:
            self.publish_event(KubeProxyEvent())
