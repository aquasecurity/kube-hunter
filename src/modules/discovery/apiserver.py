import requests
import logging

from ...core.types import Discovery
from ...core.events import handler
from ...core.events.types import OpenPortEvent, Service, Event


class ApiServer(Service, Event):
    """The API server is in charge of all operations on the cluster."""
    def __init__(self, protocol="https"):
        Service.__init__(self, name="API Server")
        self.protocol=protocol


# Other devices could have this port open, but we can check to see if it looks like a Kubernetes node
# A Kubernetes API server will respond with a JSON message that includes a "code" field for the HTTP status code
@handler.subscribe(OpenPortEvent, predicate=lambda x: x.port==443 or x.port==6443 or x.port==8080)
class ApiServerDiscovery(Discovery):
    """API Server Discovery
    Checks for the existence of a an API Server
    """
    def __init__(self, event):
        self.event = event

    def execute(self):
        logging.debug("Attempting to discover an API server on {}:{}".format(self.event.host, self.event.port))
        self.make_request(protocol="https")
        self.make_request(protocol="http")    

    def make_request(self, protocol):
        try:
            r = requests.get("{}://{}:{}".format(protocol, self.event.host, self.event.port), verify=False)
            if ('k8s' in r.text) or ('"code"' in r.text and r.status_code is not 200): 
                self.event.role = "Master"
                self.publish_event(ApiServer(protocol=protocol))
        except requests.exceptions.SSLError:
            logging.debug("{} protocol not accepted on {}:{}".format(protocol, self.event.host, self.event.port))
        except Exception as e:
            logging.debug("{} on {}:{}".format(e, self.event.host, self.event.port))

