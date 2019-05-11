from StringIO import StringIO
from ruamel.yaml import YAML
from .base import BaseReporter

class YAMLReporter(BaseReporter):
    def get_report(self):
        yaml = YAML()
        report = {
            "nodes": self.get_nodes(),
            "services": self.get_services(),
            "vulnerabilities": self.get_vulnerabilities(),
            "hunting_hunters_statistics": self.get_hunting_hunters_statistics()
        }
        output = StringIO()
        yaml.dump(report, output)
        return output.getvalue()
