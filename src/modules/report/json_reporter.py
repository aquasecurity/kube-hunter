import StringIO
import json
from base import BaseReporter

class JSONReporter(BaseReporter):
    def get_report(self):
        report = {
            "nodes": self.get_nodes(),
            "services": self.get_services(),
            "vulnerabilities": self.get_vulenrabilities()
        }
        return json.dumps(report)
