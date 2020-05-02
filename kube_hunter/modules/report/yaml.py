from io import StringIO
from ruamel.yaml import YAML

from typing import Sequence, Type
from kube_hunter.core.types import HunterBase, Service, Vulnerability
from kube_hunter.modules.report.base import BaseReporter


class YAMLReporter(BaseReporter):
    def get_report(
        self,
        services: Sequence[Service],
        vulnerabilities: Sequence[Vulnerability],
        hunters: Sequence[Type[HunterBase]],
        statistics: bool = False,
        mapping: bool = False,
    ) -> str:
        report = {
            "nodes": self.get_nodes(services),
            "services": self.get_services(services),
            "vulnerabilities": self.get_vulnerabilities(vulnerabilities),
            "kburl": "https://aquasecurity.github.io/kube-hunter/kb/{vid}",
        }

        if statistics:
            report["hunter_statistics"] = self.get_hunter_statistics(hunters)

        output = StringIO()
        yaml = YAML()
        yaml.dump(report, output)

        return output.getvalue()
