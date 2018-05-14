from events import handler, OpenPortEvent, KubeDashboardEvent
import requests

@handler.subscribe(OpenPortEvent, predicate=lambda x: x.port == 30000)
class KubeDashboard(object):
    def __init__(self, task):
        self.task = task
        self.host = task.host
        self.port = task.port 

    @property
    def secure(self):
        # TODO: insert logic for detremining a secure/insecure dashboard is there
        return False

    def execute(self):
        handler.publish_event(KubeDashboardEvent(host=self.host, port=self.port, secure=self.secure))
