import logging

class Event(object):
    def __init__(self):
        self.previous = None

    # newest attribute gets selected first
    def __getattr__(self, name):
        if name == "previous":
            return None
        for event in self.history:
            if name in event.__dict__:
                return event.__dict__[name]

    # returns the event history ordered from newest to oldest
    @property
    def history(self):
        previous, history = self.previous, list()
        while previous:
            history.append(previous)
            previous = previous.previous
        return history

class ServiceEvent(object):
    pass


""" Discovery/Hunting Events """
class NewHostEvent(Event):
    def __init__(self, host):
        self.host = host
    
    def __str__(self):
        return str(self.host)

class OpenPortEvent(Event):
    def __init__(self, port):
        self.port = port
    
    def __str__(self):
        return str(self.port)

class HostScanEvent(Event):
    def __init__(self, interal=True, localhost=True):
        self.internal = interal
        self.localhost = localhost

class KubeDashboardEvent(Event, ServiceEvent):
    def __init__(self, path="/", secure=False):
        self.path = path
        self.secure
        pass

class ReadOnlyKubeletEvent(Event, ServiceEvent):
    def __init__(self):
        pass

class SecureKubeletEvent(Event, ServiceEvent):
    def __init__(self):
        pass

class KubeProxyEvent(Event, ServiceEvent):
    def __init__(self):
        pass