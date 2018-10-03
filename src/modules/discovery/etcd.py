import json
import logging

import requests

from ...core.events import handler
from ...core.events.types import Event, OpenPortEvent, Service
from ...core.types import Hunter

"""Etcd is a DB that stores cluster's data,
    it contains configuration and current state information, and might contain secrets"""
#services:

class etcdAccessEvent(Service, Event):
    """Etcd is a DB that stores cluster's data, it contains configuration and current state information, and might contain secrets"""
    def __init__(self):
        Service.__init__(self, name="Etcd Access")



@handler.subscribe(OpenPortEvent, predicate= lambda p: p.port == 2379)
class etcdRemoteAccess(Hunter):
    """Etcd Remote Access
    Checks for remote availability of etcd, version, read access, write access
    """
    def __init__(self, event):
        self.event = event

    def execute(self):
        try:
            self.publish_event(etcdAccessEvent())
        except Exception as e:
            import traceback
            traceback.print_exc()

