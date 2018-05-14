from events import handler, NewHostEvent, OpenPortEvent
from socket import socket

default_ports = [8001, 10250, 10255, 30000]

@handler.subscribe(NewHostEvent)
class PortDiscovery(object):
    def __init__(self, task):
        self.host = task.host
        self.port = task.port

    def execute(self):
        for single_port in default_ports:
            if self.test_connection(self.host, single_port):
                handler.publish_event(OpenPortEvent(host=self.host, port=single_port))

    @staticmethod
    def test_connection(host, port):
        s = socket()
        s.settimeout(1)
        success = s.connect_ex((str(host), port))
        s.close()
        if success == 0:
            return True
        return False
