from events import handler, OpenPortEvent, KubeProxyEvent
from collections import defaultdict
from requests import get
import logging

@handler.subscribe(OpenPortEvent, predicate=lambda x: x.port == 8001)
class KubeProxy(object):
    def __init__(self, event):
        self.event = event
        self.host = event.host
        self.port = event.port or 8001

    @property
    def accesible(self):
        return True

    def execute(self):
        if self.accesible:
            handler.publish_event(KubeProxyEvent())        
            