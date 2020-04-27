# flake8: noqa: E402
from kube_hunter.conf import Config, set_config

set_config(Config())

from kube_hunter.modules.report import get_reporter, get_dispatcher
from kube_hunter.modules.report.factory import (
    YAMLReporter,
    JSONReporter,
    PlainReporter,
    HTTPDispatcher,
    STDOUTDispatcher,
)


def test_reporters():
    test_cases = [
        ("plain", PlainReporter),
        ("json", JSONReporter),
        ("yaml", YAMLReporter),
        ("notexists", PlainReporter),
    ]

    for report_type, expected in test_cases:
        actual = get_reporter(report_type)
        assert type(actual) is expected


def test_dispatchers():
    test_cases = [
        ("stdout", STDOUTDispatcher),
        ("http", HTTPDispatcher),
        ("notexists", STDOUTDispatcher),
    ]

    for dispatcher_type, expected in test_cases:
        actual = get_dispatcher(dispatcher_type)
        assert type(actual) is expected
