import logging
import threading

from kube_hunter.conf import config
from kube_hunter.core.events import handler
from kube_hunter.core.events.types import Event, Service, Vulnerability, HuntFinished, HuntStarted, ReportDispatched

logger = logging.getLogger(__name__)

global services_lock
services_lock = threading.Lock()
services = list()

global vulnerabilities_lock
vulnerabilities_lock = threading.Lock()
vulnerabilities = list()

hunters = handler.all_hunters


@handler.subscribe(Service)
@handler.subscribe(Vulnerability)
class Collector(object):
    def __init__(self, event=None):
        self.event = event

    def execute(self):
        """function is called only when collecting data"""
        global services
        global vulnerabilities
        bases = self.event.__class__.__mro__
        if Service in bases:
            with services_lock:
                services.append(self.event)
            logger.info(f"Found open service \"{self.event.get_name()}\" at {self.event.location()}")
        elif Vulnerability in bases:
            with vulnerabilities_lock:
                vulnerabilities.append(self.event)
            logger.info(f"message=\"Found vulnerability\" name=\"{self.event.get_name()}\" "
                        f"type=\"vulnerability\" location=\"{self.event.location()}\" "
                        f"description=\"{self.event.explain()}\"")


class TablesPrinted(Event):
    pass


@handler.subscribe(HuntFinished)
class SendFullReport(object):
    def __init__(self, event):
        self.event = event

    def execute(self):
        report = config.reporter.get_report(statistics=config.statistics, mapping=config.mapping)
        config.dispatcher.dispatch(report)
        handler.publish_event(ReportDispatched())
        handler.publish_event(TablesPrinted())


@handler.subscribe(HuntStarted)
class StartedInfo(object):
    def __init__(self, event):
        self.event = event

    def execute(self):
        logger.info("~ Started")
        logger.info("~ Discovering Open Kubernetes Services...")
