import StringIO

from ruamel.yaml import YAML
from base import BaseReporter

class YAMLReporter(BaseReporter):
    def get_report(self):
        yaml = YAML()
        report = {
            "nodes": self.get_nodes(),
            "services": self.get_services(),
            "vulnerabilities": self.get_vulnerabilities()
        }
        output = StringIO.StringIO()
        yaml.dump(report, output)
        return output.getvalue()