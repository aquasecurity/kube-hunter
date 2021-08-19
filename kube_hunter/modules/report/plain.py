from prettytable import ALL, PrettyTable

from kube_hunter.modules.report.base import BaseReporter, BASE_KB_LINK
from kube_hunter.modules.report.collector import (
    services,
    vulnerabilities,
    hunters,
    services_lock,
    vulnerabilities_lock,
)

EVIDENCE_PREVIEW = 100
MAX_TABLE_WIDTH = 20


class PlainReporter(BaseReporter):
    def get_report(self, *, statistics=None, mapping=None, **kwargs):
        """generates report tables"""
        output = ""

        with vulnerabilities_lock:
            vulnerabilities_len = len(vulnerabilities)

        hunters_len = len(hunters.items())

        with services_lock:
            services_len = len(services)

        if services_len:
            output += self.nodes_table()
            if not mapping:
                output += self.services_table()
                if vulnerabilities_len:
                    output += self.vulns_table()
                else:
                    output += "\nNo vulnerabilities were found"
                if statistics:
                    if hunters_len:
                        output += self.hunters_table()
                    else:
                        output += "\nNo hunters were found"
        else:
            if vulnerabilities_len:
                output += self.vulns_table()
            output += "\nKube Hunter couldn't find any clusters"
        return output

    def nodes_table(self):
        nodes_table = PrettyTable(["Type", "Location"], hrules=ALL)
        nodes_table.align = "l"
        nodes_table.max_width = MAX_TABLE_WIDTH
        nodes_table.padding_width = 1
        nodes_table.sortby = "Type"
        nodes_table.reversesort = True
        nodes_table.header_style = "upper"
        id_memory = set()
        services_lock.acquire()
        for service in services:
            if service.event_id not in id_memory:
                nodes_table.add_row(["Node/Master", service.host])
                id_memory.add(service.event_id)
        nodes_ret = f"\nNodes\n{nodes_table}\n"
        services_lock.release()
        return nodes_ret

    def services_table(self):
        services_table = PrettyTable(["Service", "Location", "Description"], hrules=ALL)
        services_table.align = "l"
        services_table.max_width = MAX_TABLE_WIDTH
        services_table.padding_width = 1
        services_table.sortby = "Service"
        services_table.reversesort = True
        services_table.header_style = "upper"
        with services_lock:
            for service in services:
                services_table.add_row(
                    [service.get_name(), f"{service.host}:{service.port}{service.get_path()}", service.explain()]
                )
            detected_services_ret = f"\nDetected Services\n{services_table}\n"
        return detected_services_ret

    def vulns_table(self):
        column_names = [
            "ID",
            "Location",
            "MITRE Category",
            "Vulnerability",
            "Description",
            "Evidence",
        ]
        vuln_table = PrettyTable(column_names, hrules=ALL)
        vuln_table.align = "l"
        vuln_table.max_width = MAX_TABLE_WIDTH
        vuln_table.sortby = "MITRE Category"
        vuln_table.reversesort = True
        vuln_table.padding_width = 1
        vuln_table.header_style = "upper"

        with vulnerabilities_lock:
            for vuln in vulnerabilities:
                evidence = str(vuln.evidence)
                if len(evidence) > EVIDENCE_PREVIEW:
                    evidence = evidence[:EVIDENCE_PREVIEW] + "..."

                row = [
                    vuln.get_vid(),
                    vuln.location(),
                    vuln.category.get_name(),
                    vuln.get_name(),
                    vuln.explain(),
                    evidence,
                ]
                vuln_table.add_row(row)
        return (
            "\nVulnerabilities\n"
            "For further information about a vulnerability, search its ID in: \n"
            f"{BASE_KB_LINK}\n{vuln_table}\n"
        )

    def hunters_table(self):
        column_names = ["Name", "Description", "Vulnerabilities"]
        hunters_table = PrettyTable(column_names, hrules=ALL)
        hunters_table.align = "l"
        hunters_table.max_width = MAX_TABLE_WIDTH
        hunters_table.sortby = "Name"
        hunters_table.reversesort = True
        hunters_table.padding_width = 1
        hunters_table.header_style = "upper"

        hunter_statistics = self.get_hunter_statistics()
        for item in hunter_statistics:
            hunters_table.add_row([item.get("name"), item.get("description"), item.get("vulnerabilities")])
        return f"\nHunter Statistics\n{hunters_table}\n"
