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
            for service in services:
                serviceAdded = False
                service_location = service["location"]
                service_ip = service["location"].split(":")[0]
                if service_ip == node_location:
                    for vulnerability in vulnerabilities:
                        vulnerability_location = vulnerability["location"]
                        if vulnerability_location == service_location:
                            entry = create_entry(node, service, vulnerability)
                            flattenedEntries.append(entry)
                            nodeAdded = True
                            serviceAdded = True
                    if not serviceAdded:
                        entry = create_entry(node, service)
                        flattenedEntries.append(entry)
                        nodeAdded = True
            if not nodeAdded:
                entry = create_entry(node)
                flattenedEntries.append(entry)
        for logEntry in flattenedEntries:
            print(json.dumps(logEntry))
        return


def create_entry(node={}, service={}, vulnerability={}):
    flattenedEntry = {}
    prefix_dict_keys(node, "node", flattenedEntry)
    prefix_dict_keys(service, "service", flattenedEntry)
    prefix_dict_keys(vulnerability, "vulnerability", flattenedEntry)
    return flattenedEntry


def prefix_dict_keys(data, prefix, entry):
    for key in data.keys():
        prefixed_key = prefix + "_" + key
        entry[prefixed_key] = data[key]
