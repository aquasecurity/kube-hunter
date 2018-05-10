import events
import requests

class KubeDashboard(object):
    def __init__(self, task):
        self.task = task
        self.host = task['host']
        self.port = task['port'] or 80
        pass

    def execute(self):
        # TODO: insert logic for detremining dashboard/insecure dashboard is there
        events.handler.publish_event('KUBE_DASHBOARD', {'host': self.host, 'port': self.port})


events.handler.subscribe_event('OPEN_PORT_30000', KubeDashboard)
