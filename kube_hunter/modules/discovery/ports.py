import logging
from socket import socket

from kube_hunter.core.types import Discovery
from kube_hunter.core.events import handler
from kube_hunter.core.events.types import NewHostEvent, OpenPortEvent

logger = logging.getLogger(__name__)
default_ports = [8001, 8080, 10250, 10255, 30000, 443, 6443, 2379]


@handler.subscribe(NewHostEvent)
class PortDiscovery(Discovery):
    """Port Scanning
    Scans Kubernetes known ports to determine open endpoints for discovery
    """

    def __init__(self, event):
        self.event = event
        self.host = event.host
        self.port = event.port

    def execute(self):
        logger.debug(f"host {self.host} try ports: {default_ports}")
        for single_port in default_ports:
            if self.test_connection(self.host, single_port):
                logger.debug(f"Reachable port found: {single_port}")
                self.publish_event(OpenPortEvent(port=single_port))

    @staticmethod
    def test_connection(host, port):
        s = socket()
        s.settimeout(1.5)
        try:
            logger.debug(f"Scanning {host}:{port}")
            success = s.connect_ex((str(host), port))
            if success == 0:
                return True
        except Exception:
            logger.debug(f"Failed to probe {host}:{port}")
        finally:
            s.close()
        return False
