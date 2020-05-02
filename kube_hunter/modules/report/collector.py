import logging

from typing import ClassVar, List
from kube_hunter.core.events import HuntStarted
from kube_hunter.core.pubsub.subscription import Subscriber, subscribe
from kube_hunter.core.types import Service, Vulnerability

logger = logging.getLogger(__name__)


@subscribe(Service)
@subscribe(Vulnerability)
class Collector(Subscriber):
    services: ClassVar[List[Service]] = list()
    vulnerabilities: ClassVar[List[Vulnerability]] = list()

    def execute(self):
        """Function is called only when collecting data"""
        event_name = self.event.__class__.__name__

        if issubclass(type(self.event), Service):
            logger.info(f"Found open service {event_name} at {self.event.location()}")
            self.services.append(self.event)
        elif issubclass(type(self.event), Service):
            logger.info(f"Found vulnerability {event_name} in {self.event.location()}")
            self.vulnerabilities.append(self.event)
            if self.event.hunter:
                self.event.hunter.__class__.published_vulnerabilities += 1


@subscribe(HuntStarted)
class StartedInfo:
    def __init__(self, event):
        self.event = event

    def execute(self):
        logger.info("Started hunting")
        logger.info("Discovering Open Kubernetes Services")
