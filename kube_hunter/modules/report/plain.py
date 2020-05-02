from prettytable import ALL, PrettyTable

from typing import Sequence, Type
from kube_hunter.core.types import HunterBase, Service, Vulnerability
from kube_hunter.modules.report.base import BaseReporter


EVIDENCE_PREVIEW = 40
MAX_TABLE_WIDTH = 20
KB_LINK = "https://github.com/aquasecurity/kube-hunter/tree/master/docs/_kb"


class PlainReporter(BaseReporter):
    def get_report(
        self,
        services: Sequence[Service],
        vulnerabilities: Sequence[Vulnerability],
        hunters: Sequence[Type[HunterBase]],
        statistics: bool = False,
        mapping: bool = False,
    ) -> str:
        """Generates report tables"""
        output = ""

        if services:
            output += self.nodes_table(services)
            if not mapping:
                output += self.services_table(services)
                if vulnerabilities:
                    output += self.vulns_table(vulnerabilities)
                else:
                    output += "\nNo vulnerabilities were found"
                if statistics:
                    if hunters:
                        output += self.hunters_table(hunters)
                    else:
                        output += "\nNo hunters were found"
        else:
            if vulnerabilities:
                output += self.vulns_table(vulnerabilities)
            output += "\nKube Hunter couldn't find any clusters"
        return output

    def nodes_table(self, services: Sequence[Service]):
        nodes_table = PrettyTable(["Type", "Location"], hrules=ALL,)
        nodes_table.align = "l"
        nodes_table.max_width = MAX_TABLE_WIDTH
        nodes_table.padding_width = 1
        nodes_table.sortby = "Type"
        nodes_table.reversesort = True
        nodes_table.header_style = "upper"
        passed_services = set()
        for service in services:
            if service.host and service not in passed_services:  # type: ignore  # dynamic field "host"
                nodes_table.add_row(["Node/Master", service.host])  # type: ignore  # dynamic field "host"
                passed_services.add(service)
        return "\nNodes\n{}\n".format(nodes_table)

    def services_table(self, services: Sequence[Service]):
        services_table = PrettyTable(["Service", "Location", "Description"], hrules=ALL)
        services_table.align = "l"
        services_table.max_width = MAX_TABLE_WIDTH
        services_table.padding_width = 1
        services_table.sortby = "Service"
        services_table.reversesort = True
        services_table.header_style = "upper"
        for service in services:
            services_table.add_row(
                [
                    service.name,
                    f"{service.host}:{service.port}{service.path}",  # type: ignore  # dynamic fields "host" and "port"
                    service.explain(),
                ]
            )
        return f"\nDetected Services\n{services_table}\n"

    def vulns_table(self, vulnerabilities: Sequence[Vulnerability]):
        column_names = [
            "ID",
            "Location",
            "Category",
            "Vulnerability",
            "Description",
            "Evidence",
        ]
        vuln_table = PrettyTable(column_names, hrules=ALL)
        vuln_table.align = "l"
        vuln_table.max_width = MAX_TABLE_WIDTH
        vuln_table.sortby = "Category"
        vuln_table.reversesort = True
        vuln_table.padding_width = 1
        vuln_table.header_style = "upper"

        for vuln in vulnerabilities:
            evidence = str(vuln.evidence)
            if len(evidence) > EVIDENCE_PREVIEW:
                evidence = evidence[:EVIDENCE_PREVIEW] + "..."
            row = [
                vuln.vid,
                vuln.location(),
                vuln.category.name,
                vuln.name,
                vuln.explain(),
                evidence,
            ]
            vuln_table.add_row(row)
        return (
            "\nVulnerabilities\n"
            "For further information about a vulnerability, search its ID in: \n"
            f"{KB_LINK}\n{vuln_table}\n"
        )

    def hunters_table(self, hunters: Sequence[Type[HunterBase]]):
        column_names = ["Name", "Description", "Vulnerabilities"]
        hunters_table = PrettyTable(column_names, hrules=ALL)
        hunters_table.align = "l"
        hunters_table.max_width = MAX_TABLE_WIDTH
        hunters_table.sortby = "Name"
        hunters_table.reversesort = True
        hunters_table.padding_width = 1
        hunters_table.header_style = "upper"

        hunter_statistics = self.get_hunter_statistics(hunters)
        for item in hunter_statistics:
            hunters_table.add_row([item["name"], item["description"], item["vulnerabilities"]])
        return f"\nHunter Statistics\n{hunters_table}\n"
