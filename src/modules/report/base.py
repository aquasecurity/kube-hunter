from collector import services, vulnerabilities, services_lock, vulnerabilities_lock

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
        vulnerabilities_data = [{"location": "{}:{}".format(vuln.host, vuln.port) if vuln.host else "",
                 "category": vuln.category.name,
                 "vulnerability": vuln.get_name(),
                 "description": vuln.explain(),
                 "evidence": str(vuln.evidence)}
                for vuln in vulnerabilities]
        vulnerabilities_lock.release()
        return vulnerabilities_data
