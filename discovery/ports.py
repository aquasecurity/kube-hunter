from socket import socket
import events


default_ports = [8001, 10250, 10255, 30000]

class PortDiscovery(object):
    def __init__(self, task):
        self.host = task['host']

    def execute(self):
        for single_port in default_ports:
            if self.test_connection(self.host, single_port):
                events.handler.publish_event('OPEN_PORT_{port}'.format(port=single_port), {'host': self.host, 'port': single_port})

    @staticmethod
    def test_connection(host, port):
        s = socket()
        s.settimeout(1)
        success = s.connect_ex((str(host), port))
        s.close()
        if success == 0:
            return True
        return False


events.handler.subscribe_event('NEW_HOST', PortDiscovery)

if __name__ == "__main__":
    queue = list()
    queue.append(PortDiscovery({'host': '192.168.1.117'}))
    queue.append(PortDiscovery({'host': '192.168.1.101'}))
    for i in queue:
        i.execute()
