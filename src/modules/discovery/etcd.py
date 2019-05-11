import json
import logging

import requests

from ...core.events import handler
from ...core.events.types import Event, OpenPortEvent, Service
from ...core.types import DiscoveryHunter

# Service:

class EtcdAccessEvent(Service, Event):
    """Etcd is a DB that stores cluster's data, it contains configuration and current state information, and might contain secrets"""
    def __init__(self):
        Service.__init__(self, name="Etcd")



@handler.subscribe(OpenPortEvent, predicate= lambda p: p.port == 2379)
class EtcdRemoteAccess(DiscoveryHunter):
    """Etcd service
    check for the existence of etcd service
    """
    def __init__(self, event):
        self.event = event

    def execute(self):
        self.publish_event(EtcdAccessEvent())
