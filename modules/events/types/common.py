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


""" Information Fathers """
# TODO: make explain an abstract method.
class ServiceEvent(object):
    def __init__(self, name, data=""):
        self.name = name
        self.data = data

    def explain(self):
        return self.data

class Vulnerability(object):
    def __init__(self, name, data=""):
        self.name = name
        self.data = data

    def explain(self):
        return self.data



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
    def __init__(self, pod=False):
        self.pod = pod
        self.auth_token = self.get_auth_token()
        self.client_cert = self.get_client_cert()

    def get_auth_token(self):
        if self.pod:
            with open("/run/secrets/kubernetes.io/serviceaccount/token") as token_file:
                return token_file.read()
        return None

    def get_client_cert(self):
        if self.pod:
            return "/run/secrets/kubernetes.io/serviceaccount/ca.crt" 
        return None


class KubeDashboardEvent(Event, ServiceEvent):
    def __init__(self, path="/", secure=False):
        self.path = path
        self.secure

class ReadOnlyKubeletEvent(Event, ServiceEvent):
    def __init__(self):
        ServiceEvent.__init__(self, name="Kubelet API (readonly)")

class SecureKubeletEvent(Event, ServiceEvent):
    def __init__(self, cert=False, token=False):
        self.cert = cert
        self.token = token
        ServiceEvent.__init__(self, name="Kubelet API") 

class KubeProxyEvent(Event, ServiceEvent):
    def __init__(self):
        ServiceEvent.__init__(self, name="Kubernetes Proxy")        