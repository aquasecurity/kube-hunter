from io import StringIO
from ruamel.yaml import YAML
from .base import BaseReporter
from __main__ import config


class YAMLReporter(BaseReporter):
    def get_report(self):
        yaml = YAML()
        report = {
            "nodes": self.get_nodes(),
            "services": self.get_services(),
            "vulnerabilities": self.get_vulnerabilities(),
        }

        if config.statistics:
            report["hunter_statistics"] = self.get_hunter_statistics()

        output = StringIO()
        yaml.dump(report, output)
        return output.getvalue()
