from kube_hunter.core.events.event_handler import handler
from kube_hunter.core.events.types import Event, OpenPortEvent, Service
from kube_hunter.core.types import Discovery


class EtcdAccessEvent(Service, Event):
    """Etcd is a DB that stores cluster's data, it contains configuration and current
    state information, and might contain secrets"""

    def __init__(self):
        Service.__init__(self, name="Etcd")


@handler.subscribe(OpenPortEvent, predicate=lambda p: p.port == 2379)
class EtcdRemoteAccess(Discovery):
    """Etcd service
    check for the existence of etcd service
    """

    def __init__(self, event):
        self.event = event

    def execute(self):
        self.publish_event(EtcdAccessEvent())
