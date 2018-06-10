import logging
from ..types import Hunter

import requests

from ..events import handler
from ..discovery.dashboard import KubeDashboardEvent

@handler.subscribe(KubeDashboardEvent)
class KubeDashboard(Hunter):
    def __init__(self, event):
        self.event = event

    def execute(self):
        # TODO: implement dashboard hunting
        pass