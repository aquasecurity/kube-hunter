import requests
import logging

from ...core.types import Hunter
from ...core.events import handler
from ...core.events.types import OpenPortEvent, Service, Event

class ReadOnlyKubeletEvent(Service, Event):
    """The read-only port on the kubelet serves health probing endpoints, and is relied upon by many kubernetes componenets"""
    def __init__(self):
        Service.__init__(self, name="Kubelet API (readonly)")


class ApiServer(Service, Event):
    """The API server is in charge of all operations on the cluster."""
    def __init__(self):
        Service.__init__(self, name="API Server")

@handler.subscribe(OpenPortEvent, predicate=lambda x: x.port==443 or x.port==6443)
class ApiServerDiscovery(Hunter):
    """Api Server Discovery
    Checks for the existence of a an Api Server
    """
    def __init__(self, event):
        self.event = event

    def execute(self):
        logging.debug("Attempting to discover an Api server")
        main_request = requests.get("https://{}:{}".format(self.event.host, self.event.port), verify=False).text
        if "code" in main_request:
            self.event.role = "Master"
        self.publish_event(ApiServer())
