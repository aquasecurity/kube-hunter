import logging
from prettytable import PrettyTable
from src.core.events import handler
from src.core.events.types import Vulnerability, Information, Service
from src.modules.discovery.kubelet import KubeletExposedHandler

services = list()
vulnerabilities = list()

@handler.subscribe(Vulnerability)
class VulnerabilityReport(object):
    def __init__(self, event):
        self.vulnerability = event

    def execute(self):
        logging.info("[VULNERABILITY - {name}] {desc}".format(
            name=self.vulnerability.get_name(),
            desc=self.vulnerability.explain(),
        ))
        vulnerabilities.append(self.vulnerability)

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

def print_results(active):
    services_table = PrettyTable(["Service", "Location", "Description"])    
    for service in services:
        services_table.add_row([service.get_name(), "{}:{}{}".format(service.host, service.port, service.get_path()), service.explain()])
    
    column_names = ["Location", "From Component", "Vulnerability", "Description"]
    if active: column_names.append("Proof")

    vuln_table = PrettyTable(column_names)
    for vuln in vulnerabilities:
        row = ["{}:{}".format(vuln.host, vuln.port), vuln.component.name, vuln.get_name(), vuln.explain()]
        if active: row.append(vuln.attrs)
        vuln_table.add_row(row)
        
    print "\nOpen Services:"
    print services_table
    print "\nVulnerabilities:"
    print vuln_table
    