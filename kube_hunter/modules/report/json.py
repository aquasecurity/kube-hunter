import json

from kube_hunter.modules.report.base import BaseReporter


class JSONReporter(BaseReporter):
    def get_report(self, **kwargs):
        report = super().get_report(**kwargs)
        return json.dumps(report)
