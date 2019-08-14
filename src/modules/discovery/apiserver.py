import json
import requests
import logging
from enum import Enum

from ...core.types import Discovery
from ...core.events import handler
from ...core.events.types import OpenPortEvent, Service, Event, EventFilterBase

KNOWN_API_PORTS = [443, 6443, 8080]

class K8sApiService(Service, Event):
    """A Kubernetes API service"""
    def __init__(self, protocol="https"):
        Service.__init__(self, name="Unrecognized K8s API")
        self.protocol = protocol


class ApiServer(Service, Event):
    """The API server is in charge of all operations on the cluster."""
    def __init__(self):
        Service.__init__(self, name="API Server")
        
class MetricsServer(Service, Event):
    """The Metrics server is in charge of providing resource usage metrics for pods and nodes to the API server."""
    def __init__(self):
        Service.__init__(self, name="Metrics Server")


# Other devices could have this port open, but we can check to see if it looks like a Kubernetes node
# A Kubernetes API server will respond to a get to /version or respond with a JSON message that includes a "code" field for the HTTP status code
@handler.subscribe(OpenPortEvent, predicate=lambda x: x.port in KNOWN_API_PORTS)
class ApiServiceDiscovery(Discovery):
    """API Service Discovery
    Checks for the existence of K8s API Services
    """
    def __init__(self, event):
        self.event = event
        self.session = requests.Session()
    
    def execute(self):
        logging.debug("Attempting to discover an API service on {}:{}".format(self.event.host, self.event.port))
        protocols = ["http", "https"]
        for protocol in protocols:
            if self.has_api_behaviour(protocol):
                self.publish_event(K8sApiService(protocol))

    def has_api_behaviour(self, protocol):
        try:
            r = self.session.get("{}://{}:{}".format(protocol, self.event.host, self.event.port))
            if ('k8s' in r.text) or ('"code"' in r.text and r.status_code is not 200):
                return True
        except requests.exceptions.SSLError:
            logging.debug("{} protocol not accepted on {}:{}".format(protocol, self.event.host, self.event.port))
        except Exception as e:
            logging.debug("{} on {}:{}".format(e, self.event.host, self.event.port))


# Acts as a Filter and a Discovery, In the case that we can classify the API,
# We filter out this event and publish specific events for the API service
@handler.subscribe(K8sApiService)
class ApiServiceClassify(EventFilterBase, Discovery):
    """API Service Classifier
    Classifies an API service
    """
    class ApiServiceTypes(Enum):
        SERVER="API Server"
        METRICS="Metrics Server"
        UNRECOGNIZED="Unreconized K8s Api Service"    

    def __init__(self, event):
        self.event = event
        self.classified = False
        self.session = requests.Session()
        self.session.verify = False
        # Using the auth token if we can, for the case that authentication is needed for our checks
        if self.event.auth_token:
            self.session.headers.update({"Authorization": "Bearer {}".format(self.event.auth_token)})
            
    def classify_using_version_endpoint(self):
        """Tries to classify by accessing /version. if could not access succeded, returns"""
        try:
            # import pytest; pytest.set_trace()
            r = self.session.get("{}://{}:{}/version".format(self.event.protocol, self.event.host, self.event.port))
            versions = r.json()
            if 'major' in versions:
                if versions.get('major') == "":
                    self.publish_event(MetricsServer())
                else:
                    self.publish_event(ApiServer())
                self.classified = True
        except Exception as e:
            logging.error("Could not access /version on API service: {}".format(e))

    def execute(self):
        # if running as pod
        if self.event.kubeservicehost:
            # if the host is the api server's IP, we know it's the Api Server
            if self.event.kubeservicehost == str(self.event.host):
                self.publish_event(ApiServer())
            else:
                self.publish_event(MetricsServer())
            self.classified = True
        # if not running as pod.
        else:
            self.classify_using_version_endpoint()

        # If some check classified the Service, 
        # we remove the registered event from handler.
        if self.classified:
            return None
        return self.event