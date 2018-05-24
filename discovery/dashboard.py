from events import handler, OpenPortEvent, KubeDashboardEvent
import requests

@handler.subscribe(OpenPortEvent, predicate=lambda x: x.port == 30000)
class KubeDashboard(object):
    def __init__(self, event):
        self.event = event
        self.host = event.host
        self.port = event.port 

    @property
    def secure(self):
        # TODO: insert logic for detremining a secure/insecure dashboard is there
        return False

    def execute(self):
        handler.publish_event(KubeDashboardEvent())
