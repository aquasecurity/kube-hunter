from logging import debug, info
from multiprocessing import Process, Queue
from socket import socket

from netaddr import IPNetwork


KUBE_PROXY_PORT = 8001
KUBELET_PORT = 10250
KUBELET_READONLY_PORT = 10255
DASHBOARD_PORT = 30000

DEFAULT_PORTS = [
    KUBE_PROXY_PORT,
    KUBELET_PORT,
    KUBELET_READONLY_PORT,
    DASHBOARD_PORT
]


def cidr_to_list(cidr):
    host_list = list(IPNetwork(cidr))
    return host_list


def test_connection(host, ports):
    result = []

    for port in ports:
        s = socket()
        s.settimeout(1)
        success = s.connect_ex((str(host), port))
        s.close()
        if success == 0:
            info("{}:{} is open".format(host, port))
            result.append("{}:{}".format(host, port))

    return result


class Worker(Process):
    _count = 0

    def __init__(self, queue):
        super(Worker, self).__init__()
        self.queue = queue
        self.name = "Worker #{}".format(Worker._count)
        Worker._count += 1

    def run(self):
        for host, ports, callback in iter(self.queue.get, None):
            debug("{}: Checking host {}".format(self.name, host))
            for result in test_connection(host, ports):
                callback(result)


class HostScanner(object):
    def __init__(self, threads=1):
        self.threads = threads

    def scan(self, cidr, ports, callback):
        queue = Queue()
        workers = []

        debug("Starting workers")
        for i in range(self.threads):
            workers.append(Worker(queue))
            workers[-1].start()

        for host in cidr_to_list(cidr):
            queue.put((host, ports, callback))

        for i in range(self.threads):
            queue.put(None)

        debug("Waiting for workers to finish")
        for worker in workers:
            worker.join()
        debug("Workers finished")
