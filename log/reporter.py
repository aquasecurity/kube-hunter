import logging
from prettytable import PrettyTable
from modules.events import handler
from modules.events.types import Vulnerability, Information, Service
from modules.discovery.kubelet import KubeletExposedHandler

services = list()
vulnerabilities = list()
informations = list()

@handler.subscribe(Vulnerability)
class VulnerabilityReport(object):
    def __init__(self, event):
        self.vulnerability = event

    def execute(self):
        logging.info("[VULNERABILITY - {name}] {desc}".format(
            name=self.vulnerability.name,
            desc=self.vulnerability.explain(),
        ))
        vulnerabilities.append(self.vulnerability)

@handler.subscribe(Information)
class ClusterInformation(object):
    def __init__(self, event):
        self.information = event

    def execute(self):
        logging.info("[INFORMATION - {name}] {desc}".format(
            name=self.information.get_name(),
            desc=self.information.explain(),
        ))
        informations.append(self.information)

@handler.subscribe(Service)
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
        services.append(self.service)



def print_results():
    services_table = PrettyTable(["Service", "Location", "Description"])    
    for service in services:
        services_table.add_row([service.get_name(), "{}:{}".format(service.host, service.port), service.explain()])
    
    vuln_table = PrettyTable(["Location", "From Component", "Vulnerability", "Description"])
    for vuln in vulnerabilities:
        vuln_table.add_row(["{}:{}".format(vuln.host, vuln.port), vuln.component.name, vuln.get_name(), vuln.explain()])
        
    print "\nOpen Services:"
    print services_table
    print "\nVulnerabilities:"
    print vuln_table
    