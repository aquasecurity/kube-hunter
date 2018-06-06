import logging
from modules.events import handler
from modules.events.types import Vulnerability, ServiceEvent

@handler.subscribe(Vulnerability)
class VulnerabilityReport(object):
    def __init__(self, event):
        self.vulnerability = event

    def execute(self):
        logging.info("[VULNERABILITY - {name}] {desc}".format(
            name=self.vulnerability.name, 
            desc=self.vulnerability.explain(), 
        ))

@handler.subscribe(ServiceEvent)
class OpenServiceReport(object):
    def __init__(self, event):
        self.service = event

    def execute(self):
        logging.info("[OPEN SERVICE - {name}] IP:{host} PORT:{port}".format(
            name=self.service.name, 
            desc=self.service.desc, 
            host=self.service.host,
            port=self.service.port
        ))