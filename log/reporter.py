import logging
from modules.events import handler
from modules.events.types import Vulnerability, ServiceEvent

@handler.subscribe(Vulnerability)
class VulnerabilityReport(object):
    def __init__(self, event):
        self.event = event

    def execute(self):
        vulnerability_type = self.event.__class__.__name__.replace("Vulnerability", "")
        logging.info("[VULNERABILITY - {type}] - {desc} | location: {host}:{port}".format(type=vulnerability_type, 
                                                                desc=self.event.desc, 
                                                                host=self.event.host,
                                                                port=self.event.port))

@handler.subscribe(ServiceEvent)
class OpenServiceReport(object):
    def __init__(self, event):
        self.event = event

    def execute(self):
        service_name = self.event.__class__.__name__.replace("Event", "")
        logging.info("[OPEN SERVICE - {name}] location: {host}:{port}".format(name=service_name, 
                                                                desc=self.event.desc, 
                                                                host=self.event.host,
                                                                port=self.event.port))