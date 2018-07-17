import json
import logging
from collections import defaultdict
import time

import requests
from prettytable import ALL, PrettyTable

from src.core.events import handler
from src.core.events.types import Service, Vulnerability, HuntStarted, HuntFinished

from __main__ import config

# [event, ...]
services = list()

# [(TypeClass, event), ...]
insights = list()

AQUA_PUSH_URL = "https://qlyscbqwl7.execute-api.us-east-1.amazonaws.com/Prod/submit?token={token}"
AQUA_RESULTS_URL = "https://kubehunter.aquasec.com/report.html?token={token}"

@handler.subscribe(Service)
@handler.subscribe(Vulnerability)
class AquaReporter(object):
    def __init__(self, event):
        self.event = event
        self.insights_by_id = defaultdict(list) 
        self.services_by_id = defaultdict(list)

    def execute(self):
        global services, insights
        bases = self.event.__class__.__mro__
        if Service in bases:
            services.append(self.event)
        elif Vulnerability in bases:
            insights.append((Vulnerability, self.event))

        if config.token:
            self.send_report(token=config.token)

    def build_sub_services(self, services_list):
        # correlation functions
        def get_insights_by_service(service):
            """generates list of insights related to a given service"""
            insights = list()
            for insight_type, insight in self.insights_by_id[service.event_id]:
                if service in insight.history:
                    insights.append((insight_type, insight))
            return insights
            
        def get_services_by_service(parent_service):
            """generates list of insights related to a given service"""
            services = list()
            for service in self.services_by_id[parent_service.event_id]:
                if service != parent_service and parent_service in service.history:
                    services.append(service)
                    self.services_by_id[parent_service.event_id].remove(service)
            return services

        current_list = list()
        for service in services_list:
            current_list.append(
            {
                "type": service.get_name(),
                "metadata": {
                    "port": service.port,
                    "path": service.get_path()
                },
                "description": service.explain()
            })
            next_services = get_services_by_service(service)
            if next_services:
                current_list[-1]["services"] = self.build_sub_services(next_services)
            current_list[-1]["insights"] = [{
                "type": insight_type.__name__,
                "name": insight.get_name(),
                "category": insight.get_category(),
                "description": insight.explain(),
                "evidence": insight.evidence if insight_type == Vulnerability else ""
            } for insight_type, insight in get_insights_by_service(service)]
        return current_list

    def send_report(self, token, finished=False):
        def generate_report():
            """function generates a report corresponding to specifications of the frontend of kubehunter"""
            for service in services:
                self.services_by_id[service.event_id].append(service)
            for insight_type, insight in insights:
                self.insights_by_id[insight.event_id].append((insight_type, insight))

            # building first layer of services (nodes)
            report = defaultdict(list)
            for _, services_list in self.services_by_id.items():
                service_report = {
                    "type": "Node", # on future, determine if slave or master
                    "metadata": {
                        "host": str(services_list[0].host)
                    },
                    # then constructing their sub services tree
                    "services": self.build_sub_services(services_list)
                } 
                report["services"].append(service_report)
            return report
        
        logging.debug("generating report")
        report = {
            'results': generate_report(),
            'metadata': {
                'finished': int(time.time()*1000) if finished else False
            } 
        } 
        logging.debug("uploading report")
        r = requests.put(AQUA_PUSH_URL.format(token=token), json=report)
        
        if r.status_code == 201: # created status
            logging.debug("report was uploaded successfully") 
            if finished:       
                print "\nSee full report at: \n{}".format(AQUA_RESULTS_URL.format(token=token))
        else:
            logging.debug("Failed sending report with:{}, {}".format(r.status_code, r.text))
            if finished:
                    print "\nCould not send report.\n{}".format(json.loads(r.text).get("status", ""))
reporter = AquaReporter({})


@handler.subscribe(HuntStarted)
class PrintUrlOnStart(object):
    def __init__(self, event):
        self.event = event

    def execute(self):
        if config.token:
            url_table = PrettyTable(["{}".format(AQUA_RESULTS_URL.format(token=config.token))], hrules=ALL)
            print "\nReport will be available at:\n{}\n".format(url_table)

@handler.subscribe(HuntFinished)
class SendFullReport(object):
    def __init__(self, event):
        self.event = event

    def execute(self):
        if config.token:
            reporter.send_report(token=config.token, finished=True)