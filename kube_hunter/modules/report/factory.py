from kube_hunter.modules.report.json import JSONReporter
from kube_hunter.modules.report.yaml import YAMLReporter
from kube_hunter.modules.report.plain import PlainReporter
from kube_hunter.modules.report.dispatchers import \
    STDOUTDispatcher, HTTPDispatcher

import logging
logger = logging.getLogger(__name__)

reporters = {
    'yaml': YAMLReporter,
    'json': JSONReporter,
    'plain': PlainReporter
}

dispatchers = {
    'stdout': STDOUTDispatcher,
    'http': HTTPDispatcher
}


def get_reporter(name):
    try:
        return reporters[name.lower()]()
    except KeyError:
        logger.warning(f"Unknown reporter \"{name}\", using plain")
        return reporters['plain']()


def get_dispatcher(name):
    try:
        return dispatchers[name.lower()]()
    except KeyError:
        logger.warning(f"Unknown dispatcher \"{name}\", using stdout")
        return dispatchers['stdout']()
