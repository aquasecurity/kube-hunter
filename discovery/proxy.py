import events
from collections import defaultdict
from requests import get

class KubeProxy(object):
    def __init__(self, task):
        self.task = task
        self.host = task['host']
        self.port = task['port'] or 8001

    @property
    def accesible(self):
        return True

    def execute(self):
        if self.accesible:
            events.handler.publish_event('KUBE_PROXY', self.task)        
            
events.handler.subscribe_event('OPEN_PORT_8001', KubeProxy)