import socket

""" Models for console """

""" Basic Models """
class Container:
    """ Basic model for Container objects """
    name = ""

    def __str__(self):
        return self.name

class Pod:
    """ Basic model for Pod objects """
    ip_address = ""
    name = ""
    namespace = ""
    containers = []

    def __str__(self):
        return f"{self.namespace}/{self.name}"

    def incluster_update(self, pod_event):
        """
        uses pod_event and other techniques to get full data on the incluster pod env data
        """
        self.namespace = pod_event.namespace
        # hostname will almost always will be the pod's name 
        self.name = socket.gethostname()


""" Cloud Models """
class Cloud:
    name = None

    def __repr__(self):
        return self.name

class UnknownCloud(Cloud):
    name = "Unknown Cloud"


""" Auth models"""
class Auth:
    token = ""

class AuthStore:
    auths = []
    selected_auth = None