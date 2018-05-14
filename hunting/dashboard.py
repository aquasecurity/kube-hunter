from events import handler, KubeDashboardEvent
import logging
import requests

@handler.subscribe(KubeDashboardEvent)
class KubeDashboard(object):
    def __init__(self, task):
        self.task = task
        
    @property
    def accessible(self):
        protocol = "https" if self.task.secure else "http"
        r = requests.get("{protocol}://{host}:{port}/{loc}".format(protocol=protocol, host=self.task.host, port=self.task.port, loc=self.task.location))
        return r.status_code == 200

    def execute(self):
        if not self.accessible:
            return

        if self.task.secure:   
            logging.info("SECURED DASHBOARD AT {}:{}/{}".format(self.task.host, self.task.port, self.task.location))
        else:
            logging.info("INSECURED DASHBOARD AT {}:{}/{}".format(self.task.host, self.task.port, self.task.location))
    
