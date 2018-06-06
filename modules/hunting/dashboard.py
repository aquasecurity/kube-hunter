import logging
from ..types import Hunter

import requests

from ..events import handler
from ..events.types import Vulnerability, Event, KubeDashboardEvent

@handler.subscribe(KubeDashboardEvent)
class KubeDashboard(Hunter):
    def __init__(self, event):
        self.event = event
        
    @property
    def accessible(self):
        protocol = "https" if self.event.secure else "http"
        r = requests.get("{protocol}://{host}:{port}{loc}".format(protocol=protocol, host=self.event.host, port=self.event.port, loc=self.event.path))
        return r.status_code == 200

    def execute(self):
        if not self.accessible:
            return

        # if self.event.secure:
            # logging.info("[OPEN SERVICE] SECURE DASHBOARD - {}:{}{}".format(self.event.host, self.event.port, self.event.path))        
        # else:
            # logging.info("[OPEN SERVICE] INSECURE DASHBOARD - {}:{}{}".format(self.event.host, self.event.port, self.event.path))            
