import logging
import requests
from collections import defaultdict

from ...core.util import get_client_cert
from ...core.types import Hunter

from requests import get

from ...core.events import handler
from ...core.events.types import Service, Event, OpenPortEvent

class KubeProxyEvent(Event, Service):
    """proxies from a localhost address to the Kubernetes apiserver"""
    def __init__(self):
        Service.__init__(self, name="Kubernetes Proxy") 

@handler.subscribe(OpenPortEvent, predicate=lambda x: x.port == 8001)
class KubeProxy(Hunter):
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
        r = requests.get("http://{host}:{port}/api/v1".format(host=self.host, port=self.port), cert=get_client_cert())
        if r.status_code == 200 and "APIResourceList" in r.text:
            return True

    def execute(self):
        if self.accesible:
            self.publish_event(KubeProxyEvent())
