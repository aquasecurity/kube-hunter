import logging
from collections import defaultdict
from ..types import Hunter

from requests import get

from ..events import handler
from ..events.types import KubeProxyEvent, OpenPortEvent


@handler.subscribe(OpenPortEvent, predicate=lambda x: x.port == 8001)
class KubeProxy(Hunter):
    def __init__(self, event):
        self.event = event
        self.host = event.host
        self.port = event.port or 8001

    @property
    def accesible(self):
        return True

    def execute(self):
        if self.accesible:
            self.publish_event(KubeProxyEvent())        
