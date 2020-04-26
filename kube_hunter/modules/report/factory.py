import logging

from kube_hunter.modules.report.json import JSONReporter
from kube_hunter.modules.report.yaml import YAMLReporter
from kube_hunter.modules.report.plain import PlainReporter
from kube_hunter.modules.report.dispatchers import STDOUTDispatcher, HTTPDispatcher

logger = logging.getLogger(__name__)

DEFAULT_REPORTER = "plain"
reporters = {
    "yaml": YAMLReporter,
    "json": JSONReporter,
    "plain": PlainReporter,
}

DEFAULT_DISPATCHER = "stdout"
dispatchers = {
    "stdout": STDOUTDispatcher,
    "http": HTTPDispatcher,
}


def get_reporter(name):
    try:
        return reporters[name.lower()]()
    except KeyError:
        logger.warning(f'Unknown reporter "{name}", using f{DEFAULT_REPORTER}')
        return reporters[DEFAULT_REPORTER]()


def get_dispatcher(name):
    try:
        return dispatchers[name.lower()]()
    except KeyError:
        logger.warning(f'Unknown dispatcher "{name}", using {DEFAULT_DISPATCHER}')
        return dispatchers[DEFAULT_DISPATCHER]()
