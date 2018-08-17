import StringIO

from ruamel.yaml import YAML

from collector import services, vulnerabilities


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
        node_locations  = set()
        for service in services:
            node_location = str(service.host)
            if node_location not in node_locations:
                nodes.append({"type": "Node/Master", "location": str(service.host)})
                node_locations.add(node_location)
        return nodes

    def get_services(self):
        return [{"service": service.get_name(),
                 "location": "{}:{}{}".format(service.host, service.port, service.get_path()),
                 "description": service.explain()}
                for service in services]

    def get_vulenrabilities(self):
        return [{"location": "{}:{}".format(vuln.host, vuln.port) if vuln.host else "",
                 "category": vuln.category.name,
                 "vulnerability": vuln.get_name(),
                 "description": vuln.explain(),
                 "evidence": str(vuln.evidence)}
                for vuln in vulnerabilities]
