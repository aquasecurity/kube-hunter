import json
from .base import BaseReporter
from __main__ import config


class JSONReporter(BaseReporter):
    def get_report(self):
        report = {
            "nodes": self.get_nodes(),
            "services": self.get_services(),
            "vulnerabilities": self.get_vulnerabilities(),
        }

        if config.statistics:
            report["hunter_statistics"] = self.get_hunter_statistics()

        return json.dumps(report)
