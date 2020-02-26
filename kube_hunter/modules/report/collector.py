import logging
import threading

from kube_hunter.conf import config
from kube_hunter.core.events import handler
from kube_hunter.core.events.types import Event, Service, Vulnerability, HuntFinished, HuntStarted, ReportDispatched


global services_lock
services_lock = threading.Lock()
services = list()

global vulnerabilities_lock
vulnerabilities_lock = threading.Lock()
vulnerabilities = list()

hunters = handler.all_hunters


def console_trim(text, prefix=' '):
    a = text.split(" ")
    b = a[:]
    total_length = 0
    count_of_inserts = 0
    for index, value in enumerate(a):
        if (total_length + (len(value) + len(prefix))) >= 80:
            b.insert(index + count_of_inserts, '\n')
            count_of_inserts += 1
            total_length = 0
        else:
            total_length += len(value) + len(prefix)
    return '\n'.join([prefix + line.strip(' ') for line in ' '.join(b).split('\n')])


def wrap_last_line(text, prefix='| ', suffix='|_'):
    lines = text.split('\n')
    lines[-1] = lines[-1].replace(prefix, suffix, 1)
    return '\n'.join(lines)


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
            import datetime
            logging.info("|\n| {name}:\n|   type: open service\n|   service: {name}\n|_  location: {location}".format(
                name=self.event.get_name(),
                location=self.event.location(),
                time=datetime.time()
            ))
        elif Vulnerability in bases:
            with vulnerabilities_lock:
                vulnerabilities.append(self.event)
            logging.info(
                "|\n| {name}:\n|   type: vulnerability\n|   location: {location}\n|   description: \n{desc}".format(
                    name=self.event.get_name(),
                    location=self.event.location(),
                    desc=wrap_last_line(console_trim(self.event.explain(), '|     '))
                ))


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
        logging.info("~ Started")
        logging.info("~ Discovering Open Kubernetes Services...")
