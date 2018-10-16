import StringIO

from ruamel.yaml import YAML

from collector import services, vulnerabilities
import threading

class YAMLReporter(object):
    def get_report(self):
        yaml = YAML()
        report = {
            "nodes": self.get_nodes(),
            "services": self.get_services(),
            "vulnerabilities": self.get_vulenrabilities()
        }
        output = StringIO.StringIO()
        yaml.dump(report, output)
        return output.getvalue()

    def get_nodes(self):
        nodes = list()
        node_locations = set()
        tlock = threading.Lock
        tlock.acquire()
        for service in services:
            node_location = str(service.host)
            if node_location not in node_locations:
                nodes.append({"type": "Node/Master", "location": str(service.host)})
                node_locations.add(node_location)
        tlock.release()
        return nodes

    def get_services(self):
        tlock = threading.Lock
        tlock.acquire()
        services_data = [{"service": service.get_name(),
                 "location": "{}:{}{}".format(service.host, service.port, service.get_path()),
                 "description": service.explain()}
                for service in services]
        tlock.release()
        return services_data

    def get_vulenrabilities(self):
        tlock = threading.Lock
        tlock.acquire()
        vulnerabilities_data = [{"location": "{}:{}".format(vuln.host, vuln.port) if vuln.host else "",
                 "category": vuln.category.name,
                 "vulnerability": vuln.get_name(),
                 "description": vuln.explain(),
                 "evidence": str(vuln.evidence)}
                for vuln in vulnerabilities]
        tlock.release()
        return vulnerabilities_data
