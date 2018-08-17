import logging

from __main__ import config
from src.core.events import handler
from src.core.events.types import Event, Service, Vulnerability, HuntFinished, HuntStarted

services = list()
vulnerabilities = list()


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
        global services, vulnerabilities
        bases = self.event.__class__.__mro__
        if Service in bases:
            services.append(self.event)
            import datetime
            logging.info("|\n| {name}:\n|   type: open service\n|   service: {name}\n|_  host: {host}:{port}".format(
                host=self.event.host,
                port=self.event.port,
                name=self.event.get_name(),
                time=datetime.time()
            ))

        elif Vulnerability in bases:
            vulnerabilities.append(self.event)
            logging.info(
                "|\n| {name}:\n|   type: vulnerability\n|   host: {host}:{port}\n|   description: \n{desc}".format(
                    name=self.event.get_name(),
                    host=self.event.host,
                    port=self.event.port,
                    desc=wrap_last_line(console_trim(self.event.explain(), '|     '))
                ))


class TablesPrinted(Event):
    pass


@handler.subscribe(HuntFinished)
class SendFullReport(object):
    def __init__(self, event):
        self.event = event

    def execute(self):
        report = config.reporter.get_report()
        if config.report == "plain":
            logging.info("\n{div}\n{report}".format(div="-" * 10, report=report))
        else:
            print(report)
        handler.publish_event(TablesPrinted())


@handler.subscribe(HuntStarted)
class StartedInfo(object):
    def __init__(self, event):
        self.event = event

    def execute(self):
        logging.info("~ Started")
        logging.info("~ Discovering Open Kubernetes Services...")
