from .collector import services, vulnerabilities, hunters, services_lock, vulnerabilities_lock
from src.core.types import Discovery
from __main__ import config


class BaseReporter(object):
    def get_nodes(self):
        nodes = list()
        node_locations = set()
        services_lock.acquire()
        for service in services:
            node_location = str(service.host)
            if node_location not in node_locations:
                nodes.append({"type": "Node/Master", "location": str(service.host)})
                node_locations.add(node_location)
        services_lock.release()
        return nodes

    def get_services(self):
        services_lock.acquire()
        services_data = [{"service": service.get_name(),
                 "location": "{}:{}{}".format(service.host, service.port, service.get_path()),
                 "description": service.explain()}
                for service in services]
        services_lock.release()
        return services_data

    def get_vulnerabilities(self):
        vulnerabilities_lock.acquire()
        vulnerabilities_data = [{"location": vuln.location(),
                 "vid": vuln.get_vid(),
                 "category": vuln.category.name,
                 "severity": vuln.get_severity(),
                 "vulnerability": vuln.get_name(),
                 "description": vuln.explain(),
                 "evidence": str(vuln.evidence),
                 "hunter": vuln.hunter.get_name()}
                for vuln in vulnerabilities]
        vulnerabilities_lock.release()
        return vulnerabilities_data

    def get_hunter_statistics(self):
        hunters_data = list()
        for hunter, docs in hunters.items():
            if not Discovery in hunter.__mro__:
                name, doc = hunter.parse_docs(docs)
                hunters_data.append({"name": name, "description": doc, "vulnerabilities": hunter.publishedVulnerabilities})
        return hunters_data

    def get_report(self):
        report = {
            "nodes": self.get_nodes(),
            "services": self.get_services(),
            "vulnerabilities": self.get_vulnerabilities()
        }

        if config.statistics:
            report["hunter_statistics"] = self.get_hunter_statistics()

        report["kburl"] = "https://aquasecurity.github.io/kube-hunter/kb/{vid}"

        return report
