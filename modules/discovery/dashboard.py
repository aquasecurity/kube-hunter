from ..types import Hunter

import requests

from ..events import handler
from ..events.types import KubeDashboardEvent, OpenPortEvent


@handler.subscribe(OpenPortEvent, predicate=lambda x: x.port == 30000)
class KubeDashboard(Hunter):
    def __init__(self, event):
        self.event = event
        self.host = event.host
        self.port = event.port 

    @property
    def secure(self):
        # TODO: insert logic for detremining a secure/insecure dashboard is there
        return False

    def execute(self):
        self.publish_event(KubeDashboardEvent())
