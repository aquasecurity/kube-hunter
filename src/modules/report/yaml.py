from io import StringIO
from ruamel.yaml import YAML
from .base import BaseReporter
from __main__ import config


class YAMLReporter(BaseReporter):
    def get_report(self):
        report = super().get_report()
        output = StringIO()
        yaml = YAML()
        yaml.dump(report, output)
        return output.getvalue()