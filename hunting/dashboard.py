import events
import requests
from events import safe_print

class KubeDashboard(object):
    def __init__(self, task):
        self.host = task['host']
        self.port = task['port'] or 30000

    def execute(self):
        print("KUBEDASHBOARD At: {} {}".format(self.host, self.port))
        if self.secured:    
            safe_print("SECURED DASHBOARD")
        else:
            safe_print("INSECURE DASHBOARD")
    
    @property
    def secured(self):
        try:
            r = requests.get("http://{host}:{port}/api/v1/node?itemsPerPage=100".format(host=self.host, port=self.port))
        except requests.exceptions.ConnectionError:
            return True

        ret = r.json()
        if 'listMeta' in ret:
            return False
        return True

events.handler.subscribe_event('KUBE_DASHBOARD', KubeDashboard)