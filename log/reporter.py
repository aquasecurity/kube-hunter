import logging

from prettytable import ALL, PrettyTable

from __main__ import config
from src.core.events import handler
from src.core.events.types import Service, Vulnerability

services = list()
vulnerabilities = list()

EVIDENCE_PREVIEW = 40
MAX_WIDTH_VULNS = 70
MAX_WIDTH_SERVICES = 60

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
        # TODO: Add ActiveHunter replacement by id, when a vulnerability comes from active hunter, it replaces it's predecessor 

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
    services_table = PrettyTable(["Service", "Location", "Description"], hrules=ALL)
    services_table.align="l"     
    services_table.max_width=MAX_WIDTH_SERVICES  
    services_table.padding_width=1
    services_table.sortby="Service"
    services_table.reversesort=True  
    services_table.header_style="upper"
    for service in services:
        services_table.add_row([service.get_name(), "{}:{}{}".format(service.host, service.port, service.get_path()), service.explain()])
    
    column_names = ["Location", "Category", "Vulnerability", "Description"]
    if config.active: column_names.append("Evidence")
    vuln_table = PrettyTable(column_names, hrules=ALL)
    vuln_table.align="l"
    vuln_table.max_width=MAX_WIDTH_VULNS 
    vuln_table.sortby="Category"    
    vuln_table.reversesort=True
    vuln_table.padding_width=1
    vuln_table.header_style="upper"    
    for vuln in vulnerabilities:
        row = ["{}:{}".format(vuln.host, vuln.port) if vuln.host else "", vuln.component.name, vuln.get_name(), vuln.explain()]
        if config.active: 
            evidence = str(vuln.evidence)[:EVIDENCE_PREVIEW] + "..." if len(str(vuln.evidence)) > EVIDENCE_PREVIEW else str(vuln.evidence)
            row.append(evidence)
        vuln_table.add_row(row)
        
    print 
    print "Open Services:"
    print services_table
    print 
    print "Vulnerabilities:"
    print vuln_table
