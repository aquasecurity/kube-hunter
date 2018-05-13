import events
import requests

class KubeDashboard(object):
    def __init__(self, task):
        self.task = task
        self.host = task['host']
        self.port = task['port'] if 'port' in task else 80

    @property
    def secure(self):
        # TODO: insert logic for detremining a secure/insecure dashboard is there
        return False
            
    def execute(self):
        events.handler.publish_event('KUBE_DASHBOARD', {"host": self.host, "port": self.port, "secure": self.secure})


events.handler.subscribe_event('OPEN_PORT_30000', KubeDashboard)
