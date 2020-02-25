from kube_hunter.core.types import Discovery
from kube_hunter.modules.report.collector import services, vulnerabilities, \
    hunters, services_lock, vulnerabilities_lock


class BaseReporter(object):
    def get_nodes(self):
        nodes = list()
        node_locations = set()
        with services_lock:
            for service in services:
                node_location = str(service.host)
                if node_location not in node_locations:
                    nodes.append({
                        "type": "Node/Master",
                        "location": str(service.host)
                    })
                    node_locations.add(node_location)
        return nodes

    def get_services(self):
        with services_lock:
            services_data = [{
                "service": service.get_name(),
                "location": f"{service.host}:"
                            f"{service.port}"
                            f"{service.get_path()}",
                "description": service.explain()
            } for service in services]
        return services_data

    def get_vulnerabilities(self):
        with vulnerabilities_lock:
            vulnerabilities_data = [{
                "location": vuln.location(),
                "vid": vuln.get_vid(),
                "category": vuln.category.name,
                "severity": vuln.get_severity(),
                "vulnerability": vuln.get_name(),
                "description": vuln.explain(),
                "evidence": str(vuln.evidence),
                "hunter": vuln.hunter.get_name()
            } for vuln in vulnerabilities]
        return vulnerabilities_data

    def get_hunter_statistics(self):
        hunters_data = list()
        for hunter, docs in hunters.items():
            if not Discovery in hunter.__mro__:
                name, doc = hunter.parse_docs(docs)
                hunters_data.append({
                    "name": name,
                    "description": doc,
                    "vulnerabilities": hunter.publishedVulnerabilities
                })
        return hunters_data

    def get_report(self, *, statistics, **kwargs):
        report = {
            "nodes": self.get_nodes(),
            "services": self.get_services(),
            "vulnerabilities": self.get_vulnerabilities()
        }

        if statistics:
            report["hunter_statistics"] = self.get_hunter_statistics()

        report["kburl"] = "https://aquasecurity.github.io/kube-hunter/kb/{vid}"

        return report
