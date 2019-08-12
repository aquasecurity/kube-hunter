import json
import requests
import logging

from ...core.types import Discovery
from ...core.events import handler
from ...core.events.types import OpenPortEvent, Service, Event


KNOWN_API_PORTS = [443, 6443, 8080]

class ApiServer(Service, Event):
    """The API server is in charge of all operations on the cluster."""
    def __init__(self, protocol="https"):
        Service.__init__(self, name="API Server")
        self.protocol=protocol

class MetricsServer(Service, Event):
    """The Metrics server is in charge of providing resource usage metrics for pods and nodes to the API server."""
    def __init__(self):
        Service.__init__(self, name="Metrics Server")
 
 
# Other devices could have this port open, but we can check to see if it looks like a Kubernetes node
# A Kubernetes API server will to respond to a get to /version 
@handler.subscribe(OpenPortEvent, predicate=lambda x: x.port in KNOWN_API_PORTS)
class ApiServerDiscovery(Discovery):
    """API Server Discovery
    Checks for the existence of a an API Server
    """
    def __init__(self, event):
        self.event = event

    def execute(self):
        # if were running as a pod, we only want to discover the api server from the env variable.
        if self.event.kubeservicehost and self.event.kubeservicehost != self.event.host:
            return
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


# Making sure to not subscribe to the Api Server's host
@handler.subscribe(OpenPortEvent, predicate=lambda x: x.port in KNOWN_API_PORTS and x.kubeservicehost != x.host)
class MetricsServerDiscovery(Discovery):
    """Metrics Server Discovery
    Checks for the existence of a a Metrics Server Pod
    """
    def __init__(self, event):
        self.event = event

    def execute(self):
        r = requests.get("https://{}:{}/version".format(self.event.host, self.event.port), verify=False)
        try:
            versions = json.loads(r.text)
            # major version on a metrics server will return empty
            if versions.get("major") == "":
                self.publish_event(MetricsServer())
        except Exception as e:
            logging.error("Could not access /version on metrics server at: {}".format(e))
            