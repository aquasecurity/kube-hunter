import json
from kube_hunter.modules.report.base import BaseReporter


class NDJSONReporter(BaseReporter):
    def get_report(self, **kwargs):
        report = super().get_report(**kwargs)

        nodes = report["nodes"]
        services = report["services"]
        vulnerabilities = report["vulnerabilities"]

        flattenedEntries = []
        for node in nodes:
            nodeAdded = False
            node_location = node["location"]
            node_type = node["type"]
            for service in services:
                serviceAdded = False
                service_service = service["service"]
                service_location = service["location"]
                service_description = service["description"]
                service_ip = service["location"].split(":")[0]
                if service_ip == node_location:
                    for vulnerability in vulnerabilities:
                        vulnerability_location = vulnerability["location"]
                        vulnerability_vid = vulnerability["vid"]
                        vulnerability_category = vulnerability["category"]
                        vulnerability_severity = vulnerability["severity"]
                        vulnerability_vulnerability = vulnerability["vulnerability"]
                        vulnerability_description = vulnerability["description"]
                        vulnerability_evidence = vulnerability["evidence"]
                        vulnerability_hunter = vulnerability["hunter"]
                        if vulnerability_location == service_location:
                            entry = create_entry(node_location, node_type, service_service, service_location, service_description, vulnerability_location, vulnerability_vid, vulnerability_category, vulnerability_severity, vulnerability_vulnerability, vulnerability_description, vulnerability_evidence, vulnerability_hunter)
                            flattenedEntries.append(entry)
                            nodeAdded = True
                            serviceAdded = True
                    if not serviceAdded:
                        entry = create_entry(node_location, node_type, service_service, service_location, service_description)
                        flattenedEntries.append(entry)
                        nodeAdded = True
            if not nodeAdded:
                entry = create_entry(node_location, node_type, service_service, service_location, service_description)
                flattenedEntries.append(entry)
        for logEntry in flattenedEntries:
            print(json.dumps(logEntry))
        return


def create_entry(node_location="", node_type="", service_service="", service_location="", service_description="", vulnerability_location="", vulnerability_vid="", vulnerability_category="", vulnerability_severity="", vulnerability_vulnerability="", vulnerability_description="", vulnerability_evidence="", vulnerability_hunter=""):
    flattenedEntry = {}
    flattenedEntry["node_location"] = node_location
    flattenedEntry["node_type"] = node_type
    flattenedEntry["service_service"] = service_service
    flattenedEntry["service_location"] = service_location
    flattenedEntry["service_description"] = service_description
    flattenedEntry["vulnerability_location"] = vulnerability_location
    flattenedEntry["vulnerability_vid"] = vulnerability_vid
    flattenedEntry["vulnerability_category"] = vulnerability_category
    flattenedEntry["vulnerability_severity"] = vulnerability_severity
    flattenedEntry["vulnerability_vulnerability"] = vulnerability_vulnerability
    flattenedEntry["vulnerability_description"] = vulnerability_description
    flattenedEntry["vulnerability_evidence"] = vulnerability_evidence
    flattenedEntry["vulnerability_hunter"] = vulnerability_hunter
    return flattenedEntry
