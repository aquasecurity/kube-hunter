import abc

from typing import Sequence, Type
from kube_hunter.core.types import HunterBase, Service, Vulnerability


class BaseReporter(metaclass=abc.ABCMeta):
    def get_nodes(self, services: Sequence[Service]):
        node_locations = {str(service.host) for service in services}  # type: ignore  # dynamic field "host"
        return [{"type": "Node/Master", "location": location} for location in node_locations]

    def get_services(self, services: Sequence[Service]):
        return [
            # dynamic fields "host" and "port"
            {"service": service.name, "location": f"{service.host}:{service.port}{service.path}"}  # type: ignore
            for service in services
        ]

    def get_vulnerabilities(self, vulnerabilities: Sequence[Vulnerability]):
        return [
            {
                "location": vuln.location(),
                "vid": vuln.vid,
                "category": vuln.category.name,
                "severity": vuln.category.severity,
                "vulnerability": vuln.name,
                "description": vuln.explain(),
                "evidence": vuln.evidence or "None",
                "hunter": vuln.hunter.get_name(),
            }
            for vuln in vulnerabilities
        ]

    def get_hunter_statistics(self, hunters: Sequence[Type[HunterBase]]):
        hunters_data = []
        for hunter in hunters:
            name, description = hunter.parse_docs()
            hunters_data.append(
                {"name": name, "description": description, "vulnerabilities": hunter.published_vulnerabilities}
            )
        return hunters_data

    @abc.abstractmethod
    def get_report(
        self,
        services: Sequence[Service],
        vulnerabilities: Sequence[Vulnerability],
        hunters: Sequence[Type[HunterBase]],
        statistics: bool = False,
        mapping: bool = False,
    ) -> str:
        pass
