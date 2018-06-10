import json

import requests

from ...core.events import handler
from ...core.events.types import Event, Service, OpenPortEvent
from ...core.types import Hunter

class KubeDashboardEvent(Service, Event):
    """Allows multiple arbitrary operations on the cluster from all connections"""
    def __init__(self, **kargs):
        Service.__init__(self, name="Kubernetes Dashboard", **kargs)     

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
