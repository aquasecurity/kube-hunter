from kube_hunter.modules.report.json import JSONReporter
from kube_hunter.modules.report.yaml import YAMLReporter
from kube_hunter.modules.report.plain import PlainReporter
from kube_hunter.modules.report.dispatchers import \
    STDOUTDispatcher, HTTPDispatcher

import logging


def get_reporter(name):
    reporters = {
        'yaml': YAMLReporter,
        'json': JSONReporter,
        'plain': PlainReporter
    }

    if name.lower() in reporters.keys():
        return reporters[name.lower()]()
    else:
        logging.warning('Unknown reporter selected, using plain')
        return reporters['plain']()


def get_dispatcher(name):
    dispatchers = {
        'stdout': STDOUTDispatcher,
        'http': HTTPDispatcher
    }

    if name.lower() in dispatchers.keys():
        return dispatchers[name.lower()]()
    else:
        logging.warning('Unknown dispatcher selected, using stdout')
        return dispatchers['stdout']()