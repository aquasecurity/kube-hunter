import logging

from socket import socket
from ...core.types import Hunter

from ...core.events import handler
from ...core.events.types import NewHostEvent, OpenPortEvent


default_ports = [8001, 10250, 10255, 30000, 443, 6443]

@handler.subscribe(NewHostEvent)
class PortDiscovery(Hunter):
    """Port Scanning
    Scans Kubernetes known ports to determine open endpoints for discovery
    """
    def __init__(self, event):
        self.event = event
        self.host = event.host
        self.port = event.port

    def execute(self):
        logging.debug("host {0} try ports {1}".format(self.host, default_ports))
        for single_port in default_ports:
            if self.test_connection(self.host, single_port):
                self.publish_event(OpenPortEvent(port=single_port))

    @staticmethod
    def test_connection(host, port):
        s = socket()
        s.settimeout(1.5)
        try: 
            success = s.connect_ex((str(host), port))
            if success == 0:
                return True
        except: pass
        finally: s.close()
        return False
