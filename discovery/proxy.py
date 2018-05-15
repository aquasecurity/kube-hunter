from events import handler, OpenPortEvent, KubeProxyEvent
from collections import defaultdict
from requests import get
import logging

@handler.subscribe(OpenPortEvent, predicate=lambda x: x.port == 8001)
class KubeProxy(object):
    def __init__(self, task):
        self.task = task
        self.host = task.host
        self.port = task.port or 8001

    @property
    def accesible(self):
        return True

    def execute(self):
        if self.accesible:
            handler.publish_event(KubeProxyEvent(host=self.host, port=self.port))        
            