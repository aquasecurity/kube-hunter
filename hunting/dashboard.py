import events
import requests
from events import safe_print

class KubeDashboard(object):
    def __init__(self, task):
        self.host = task['host']
        self.port = task['port'] or 30000
        self.secure = task['secure'] if 'secure' in task else False
        self.location = task["location"] if "location" in task else ""

    @property
    def accessible(self):
        protocol = "https" if self.secure else "http"
        r = requests.get("{protocol}://{host}:{port}/{loc}".format(protocol=protocol, host=self.host, port=self.port, loc=self.location))
        return r.status_code == 200

    def execute(self):
        if not self.accessible:
            return

        if self.secure:    
            safe_print("SECURED DASHBOARD AT {}:{}/{}".format(self.host, self.port, self.location))
        else:
            safe_print("INSECURE DASHBOARD AT {}:{}/{}".format(self.host, self.port, self.location))
    

events.handler.subscribe_event('KUBE_DASHBOARD', KubeDashboard)
