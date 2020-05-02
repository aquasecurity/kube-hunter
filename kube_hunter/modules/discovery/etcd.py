from kube_hunter.core.events import OpenPortEvent
from kube_hunter.core.pubsub.subscription import Event, subscribe
from kube_hunter.core.types import Discovery, Service


class EtcdAccessEvent(Service, Event):
    """Etcd is the database that stores the kubernetes cluster data, it contains configuration and current
    state information, and might contain secrets"""

    def __init__(self):
        Service.__init__(self, name="Etcd")


@subscribe(OpenPortEvent, predicate=lambda event: event.port == 2379)
class EtcdRemoteAccess(Discovery):
    """Etcd service
    check for the existence of etcd service
    """

    def execute(self):
        yield EtcdAccessEvent()
