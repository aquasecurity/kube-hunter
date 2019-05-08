from .collector import services, vulnerabilities, hunters, services_lock, vulnerabilities_lock, hunters_lock
from src.core.types import DiscoveryHunter

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

    def get_severity(self, category):
        severity = {
            "Information Disclosure": "medium",
            "Denial of Service": "medium",
            "Remote Code Execution": "high",
            "Identity Theft": "high",
            "Access Risk": "low"
        }
        return severity.get(category, "ok")

    def get_vulnerabilities(self):
        vulnerabilities_lock.acquire()
        vulnerabilities_data = [{"location": vuln.location(),
                 "category": vuln.category.name,
                 "severity": self.get_severity(vuln.category.name),
                 "vulnerability": vuln.get_name(),
                 "description": vuln.explain(),
                 "evidence": str(vuln.evidence)}
                for vuln in vulnerabilities]
        vulnerabilities_lock.release()
        return vulnerabilities_data

    def get_hunting_hunters_statistics(self):
        hunters_lock.acquire()
        hunters_data = list()
        for hunter, docs in hunters.items():
            if not DiscoveryHunter in hunter.__mro__:
                name, docs = self.parse_docs(hunter, docs)
                hunters_data.append({"name": name, "description": docs, "events": hunter.publishedEvents})
        hunters_lock.release()
        return hunters_data

    def parse_docs(self, hunter, docs):
        """returns tuple of (name, docs)"""
        if not docs:
            return hunter.__name__, "<no documentation>" 
        docs = docs.strip().split('\n')
        for i, line in enumerate(docs):
            docs[i] = line.strip()
        return docs[0], ' '.join(docs[1:]) if len(docs[1:]) else "<no documentation>"
