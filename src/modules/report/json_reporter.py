import json
from .base import BaseReporter

class JSONReporter(BaseReporter):
    def get_report(self):
        report = {
            "nodes": self.get_nodes(),
            "services": self.get_services(),
            "vulnerabilities": self.get_vulnerabilities(),
            "hunting_hunters_statistics": self.get_hunting_hunters_statistics()
        }
        return json.dumps(report)
