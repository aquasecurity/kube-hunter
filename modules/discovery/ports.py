from socket import socket
from ..types import Hunter

from ..events import handler
from ..events.types import NewHostEvent, OpenPortEvent


default_ports = [8001, 10250, 10255, 30000]

@handler.subscribe(NewHostEvent)
class PortDiscovery(Hunter):
    def __init__(self, event):
        self.event = event
        self.host = event.host
        self.port = event.port

    def execute(self):
        for single_port in default_ports:
            if self.test_connection(self.host, single_port):
                self.publish_event(OpenPortEvent(port=single_port))

    @staticmethod
    def test_connection(host, port):
        s = socket()
        s.settimeout(1.5)
        success = s.connect_ex((str(host), port))
        s.close()
        if success == 0:
            return True
        return False
