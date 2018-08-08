import json
import logging
from time import time
from collections import defaultdict

import requests
from prettytable import ALL, PrettyTable

from __main__ import config
from src.core.events import handler
from src.core.events.types import Service, Vulnerability, HuntFinished, HuntStarted

# [event, ...]
services = list()


vulnerabilities = list()

EVIDENCE_PREVIEW = 40
MAX_TABLE_WIDTH = 20

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
    def __init__(self, event=None):
        self.event = event

    def execute(self):
        """function is called only when collecting data"""
        global services, vulnerabilities
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
            vulnerabilities.append(self.event)
            logging.info(
                "|\n| {name}:\n|   type: vulnerability\n|   host: {host}:{port}\n|   description: \n{desc}".format(
                    name=self.event.get_name(),
                    host=self.event.host,
                    port=self.event.port,
                    desc=wrap_last_line(console_trim(self.event.explain(), '|     '))
                ))

    def get_tables(self):
        """generates report tables"""
        output = ""
        if len(services):
            output += nodes_table()
            if not config.mapping:
                output += services_table()
                if len(vulnerabilities):
                    output += vulns_table()
                else:
                    output += "\nNo vulnerabilities were found"
        else:
            print "\nKube Hunter couldn't find any clusters"
            # print "\nKube Hunter couldn't find any clusters. {}".format("Maybe try with --active?" if not config.active else "")
        return output

reporter = DefaultReporter()


@handler.subscribe(HuntFinished)
class SendFullReport(object):
    def __init__(self, event):
        self.event = event

    def execute(self):
        logging.info("\n{div}\n{tables}".format(div="-" * 10, tables=reporter.get_tables()))


@handler.subscribe(HuntStarted)
class StartedInfo(object):
    def __init__(self, event):
        self.event = event

    def execute(self):
        logging.info("~ Started")
        logging.info("~ Discovering Open Kubernetes Services...")


""" Tables Generation """
def nodes_table():
    nodes_table = PrettyTable(["Type", "Location"], hrules=ALL)
    nodes_table.align="l"     
    nodes_table.max_width=MAX_TABLE_WIDTH  
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
    return "\nNodes\n{}\n".format(nodes_table)


def services_table():
    services_table = PrettyTable(["Service", "Location", "Description"], hrules=ALL)
    services_table.align="l"     
    services_table.max_width=MAX_TABLE_WIDTH  
    services_table.padding_width=1
    services_table.sortby="Service"
    services_table.reversesort=True  
    services_table.header_style="upper"
    for service in services:
        services_table.add_row([service.get_name(), "{}:{}{}".format(service.host, service.port, service.get_path()), service.explain()])
    
    return "\nDetected Services\n{}\n".format(services_table)


def vulns_table():
    column_names = ["Location", "Category", "Vulnerability", "Description", "Evidence"]
    vuln_table = PrettyTable(column_names, hrules=ALL)
    vuln_table.align="l"
    vuln_table.max_width=MAX_TABLE_WIDTH 
    vuln_table.sortby="Category"    
    vuln_table.reversesort=True
    vuln_table.padding_width=1
    vuln_table.header_style="upper"    
    for vuln in vulnerabilities:
        row = ["{}:{}".format(vuln.host, vuln.port) if vuln.host else "", vuln.category.name, vuln.get_name(), vuln.explain()]
        evidence = str(vuln.evidence)[:EVIDENCE_PREVIEW] + "..." if len(str(vuln.evidence)) > EVIDENCE_PREVIEW else str(vuln.evidence)
        row.append(evidence)
        vuln_table.add_row(row)
    return "\nVulnerabilities\n{}\n".format(vuln_table)
