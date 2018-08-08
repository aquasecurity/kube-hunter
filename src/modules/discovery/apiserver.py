import requests

from ...core.types import Hunter
from ...core.events import handler
from ...core.events.types import OpenPortEvent

@handler.subscribe(OpenPortEvent, predicate=lambda x: x.port==443)
class ApiServerDiscovery(Hunter):
    """Api Server Discovery
    Checks for the existence of a an Api Server
    """
    def __init__(self, event):
        self.event = event

    def execute(self):
        main_request = requests.get("https://{}:{}".format(self.event.host, self.event.port), verify=False).text
        if "code" in main_request:
            self.event.role = "Master"