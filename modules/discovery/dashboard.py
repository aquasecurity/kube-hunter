import json

import requests

from ..events import handler
from ..events.types import Event, Service, OpenPortEvent
from ..types import Hunter

class KubeDashboardEvent(Service, Event):
    """Allows multiple arbitrary operations on the cluster from all connections"""
    def __init__(self, path="/", secure=False):
        self.path = path
        self.secure
        Service.__init__(self, name="Kubernetes Dashboard")     

@handler.subscribe(OpenPortEvent, predicate=lambda x: x.port == 30000)
class KubeDashboard(Hunter):
    def __init__(self, event):
        self.event = event
        self.host = event.host
        self.port = event.port 

    @property
    def secure(self):
        default = json.loads(requests.get("http://{}:{}/api/v1/service/default".format(self.host, self.port)).text)
        if "errors" in default and len(default["errors"]) == 0:
            return False
        return False

    def execute(self):
        if not self.secure:
            self.publish_event(KubeDashboardEvent())
