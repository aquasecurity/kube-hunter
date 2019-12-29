import json
from kube_hunter.modules.report.base import BaseReporter


class JSONReporter(BaseReporter):
    def get_report(self):
        report = super().get_report()
        return json.dumps(report)
