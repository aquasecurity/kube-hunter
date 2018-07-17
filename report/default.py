import json
import logging
from time import time
from collections import defaultdict

import requests
from prettytable import ALL, PrettyTable

from __main__ import config
from src.core.events import handler
from src.core.events.types import Service, Vulnerability, HuntFinished

# [event, ...]
services = list()

# [(TypeClass, event), ...]
insights = list()

vulnerabilities = list()

EVIDENCE_PREVIEW = 40
MAX_WIDTH_VULNS = 70
MAX_WIDTH_SERVICES = 60


def console_trim(text, prefix=' '):
    a = text.split(" ")
    b = a[:]
    total_length = 0
    count_of_inserts = 0
    for index, value in enumerate(a):
        if (total_length + (len(value) + len(prefix))) >= 80:
            b.insert(index + count_of_inserts, '\n')
            count_of_inserts += 1
            total_length = 0
        else:
            total_length += len(value) + len(prefix)
    return '\n'.join([prefix + line.strip(' ') for line in ' '.join(b).split('\n')])


def wrap_last_line(text, prefix='| ', suffix='|_'):
    lines = text.split('\n')
    lines[-1] = lines[-1].replace(prefix, suffix, 1)
    return '\n'.join(lines)


@handler.subscribe(Service)
@handler.subscribe(Vulnerability)
class DefaultReporter(object):
    """Reportes can be initiated by the event handler, and by regular decaration. for usage on end of runtime"""

    def __init__(self, event=None):
        self.event = event

    def execute(self):
        """function is called only when collecting data"""
        global services, insights
        bases = self.event.__class__.__mro__
        if Service in bases:
            services.append(self.event)
            import datetime
            logging.info("|\n| {name}:\n|   type: open service\n|   service: {name}\n|_  host: {host}:{port}".format(
                host=self.event.host,
                port=self.event.port,
                name=self.event.get_name(),
                time=datetime.time()
            ))

        elif Vulnerability in bases:
            insights.append((Vulnerability, self.event))
            vulnerabilities.append(self.event)
            logging.info(
                "|\n| {name}:\n|   type: vulnerability\n|   host: {host}:{port}\n|   description: \n{desc}".format(
                    name=self.event.get_name(),
                    host=self.event.host,
                    port=self.event.port,
                    desc=wrap_last_line(console_trim(self.event.explain(), '|     '))
                ))

    def print_tables(self):
        """generates report tables and outputs to stdout"""
        if len(services):
            print_nodes()
            if not config.mapping:
                print_services()
                print_vulnerabilities()
        else:
            print "\nKube Hunter couldn't find any clusters"
            # print "\nKube Hunter couldn't find any clusters. {}".format("Maybe try with --active?" if not config.active else "")


reporter = DefaultReporter()


@handler.subscribe(HuntFinished)
class SendFullReport(object):
    def __init__(self, event):
        self.event = event

    def execute(self):
        reporter.print_tables()


""" Tables Generation """


def print_nodes():
    return
    nodes_table = PrettyTable(["Type", "Location"], hrules=ALL)
    nodes_table.align="l"     
    nodes_table.max_width=MAX_WIDTH_SERVICES  
    nodes_table.padding_width=1
    nodes_table.sortby="Type"
    nodes_table.reversesort=True  
    nodes_table.header_style="upper"
    
    # TODO: replace with sets
    id_memory = list()
    for service in services:
        if service.event_id not in id_memory:
            nodes_table.add_row(["Node/Master", service.host])
            id_memory.append(service.event_id)
    print "Nodes:"
    print nodes_table
    print 


def print_services():
    return
    services_table = PrettyTable(["Service", "Location", "Description"], hrules=ALL)
    services_table.align="l"     
    services_table.max_width=MAX_WIDTH_SERVICES  
    services_table.padding_width=1
    services_table.sortby="Service"
    services_table.reversesort=True  
    services_table.header_style="upper"
    for service in services:
        services_table.add_row([service.get_name(), "{}:{}{}".format(service.host, service.port, service.get_path()), service.explain()])
    print "Detected Services:"
    print services_table
    print 


def print_vulnerabilities():
    return
    column_names = ["Location", "Category", "Vulnerability", "Description", "Evidence"]
    vuln_table = PrettyTable(column_names, hrules=ALL)
    vuln_table.align="l"
    vuln_table.max_width=MAX_WIDTH_VULNS 
    vuln_table.sortby="Category"    
    vuln_table.reversesort=True
    vuln_table.padding_width=1
    vuln_table.header_style="upper"    
    for vuln in vulnerabilities:
        row = ["{}:{}".format(vuln.host, vuln.port) if vuln.host else "", vuln.category.name, vuln.get_name(), vuln.explain()]
        evidence = str(vuln.evidence)[:EVIDENCE_PREVIEW] + "..." if len(str(vuln.evidence)) > EVIDENCE_PREVIEW else str(vuln.evidence)
        row.append(evidence)
        vuln_table.add_row(row)        
    print "Vulnerabilities:"
    print vuln_table
    print 
