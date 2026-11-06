# flake8: noqa: E402
import json

from requests_mock.adapter import ANY

from kube_hunter.conf import Config, set_config

set_config(Config())

from kube_hunter.modules.report.json import JSONReporter
from kube_hunter.modules.report.dispatchers import HTTPDispatcher


def test_http_dispatch_sends_a_json_object(requests_mock):
    """The JSON reporter returns a string for console output, but the HTTP
    dispatcher must send a JSON object, not a JSON-encoded string (issue #521:
    APIs rejected the double-encoded payload with 422 Unprocessable Entity)."""
    report = JSONReporter().get_report(statistics=False, mapping=False)
    assert isinstance(report, str)

    requests_mock.post(ANY, json={})
    HTTPDispatcher().dispatch(report)

    assert requests_mock.called
    body = json.loads(requests_mock.last_request.text)
    assert isinstance(body, dict)
    assert requests_mock.last_request.headers["Content-Type"] == "application/json"


def test_http_dispatch_passes_through_dict_reports(requests_mock):
    """Reporters that already return a dict keep working unchanged."""
    report = {"nodes": [], "services": [], "vulnerabilities": []}

    requests_mock.post(ANY, json={})
    HTTPDispatcher().dispatch(report)

    assert requests_mock.called
    body = json.loads(requests_mock.last_request.text)
    assert body == report
