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