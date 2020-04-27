import logging
import requests

from kube_hunter.core.types import Discovery
from kube_hunter.core.events import handler
from kube_hunter.core.events.types import OpenPortEvent, Service, Event, EventFilterBase

from kube_hunter.conf import get_config

KNOWN_API_PORTS = [443, 6443, 8080]

logger = logging.getLogger(__name__)


class K8sApiService(Service, Event):
    """A Kubernetes API service"""

    def __init__(self, protocol="https"):
        Service.__init__(self, name="Unrecognized K8s API")
        self.protocol = protocol


class ApiServer(Service, Event):
    """The API server is in charge of all operations on the cluster."""

    def __init__(self):
        Service.__init__(self, name="API Server")
        self.protocol = "https"


class MetricsServer(Service, Event):
    """The Metrics server is in charge of providing resource usage metrics for pods and nodes to the API server"""

    def __init__(self):
        Service.__init__(self, name="Metrics Server")
        self.protocol = "https"


# Other devices could have this port open, but we can check to see if it looks like a Kubernetes api
# A Kubernetes API service will respond with a JSON message that includes a "code" field for the HTTP status code
@handler.subscribe(OpenPortEvent, predicate=lambda x: x.port in KNOWN_API_PORTS)
class ApiServiceDiscovery(Discovery):
    """API Service Discovery
    Checks for the existence of K8s API Services
    """

    def __init__(self, event):
        self.event = event
        self.session = requests.Session()
        self.session.verify = False

    def execute(self):
        logger.debug(f"Attempting to discover an API service on {self.event.host}:{self.event.port}")
        protocols = ["http", "https"]
        for protocol in protocols:
            if self.has_api_behaviour(protocol):
                self.publish_event(K8sApiService(protocol))

    def has_api_behaviour(self, protocol):
        config = get_config()
        try:
            r = self.session.get(f"{protocol}://{self.event.host}:{self.event.port}", timeout=config.network_timeout)
            if ("k8s" in r.text) or ('"code"' in r.text and r.status_code != 200):
                return True
        except requests.exceptions.SSLError:
            logger.debug(f"{[protocol]} protocol not accepted on {self.event.host}:{self.event.port}")
        except Exception:
            logger.debug(f"Failed probing {self.event.host}:{self.event.port}", exc_info=True)


# Acts as a Filter for services, In the case that we can classify the API,
# We swap the filtered event with a new corresponding Service to next be published
# The classification can be regarding the context of the execution,
# Currently we classify: Metrics Server and Api Server
# If running as a pod:
# We know the Api server IP, so we can classify easily
# If not:
# We determine by accessing the /version on the service.
# Api Server will contain a major version field, while the Metrics will not
@handler.subscribe(K8sApiService)
class ApiServiceClassify(EventFilterBase):
    """API Service Classifier
    Classifies an API service
    """

    def __init__(self, event):
        self.event = event
        self.classified = False
        self.session = requests.Session()
        self.session.verify = False
        # Using the auth token if we can, for the case that authentication is needed for our checks
        if self.event.auth_token:
            self.session.headers.update({"Authorization": f"Bearer {self.event.auth_token}"})

    def classify_using_version_endpoint(self):
        """Tries to classify by accessing /version. if could not access succeded, returns"""
        config = get_config()
        try:
            endpoint = f"{self.event.protocol}://{self.event.host}:{self.event.port}/version"
            versions = self.session.get(endpoint, timeout=config.network_timeout).json()
            if "major" in versions:
                if versions.get("major") == "":
                    self.event = MetricsServer()
                else:
                    self.event = ApiServer()
        except Exception:
            logging.warning("Could not access /version on API service", exc_info=True)

    def execute(self):
        discovered_protocol = self.event.protocol
        # if running as pod
        if self.event.kubeservicehost:
            # if the host is the api server's IP, we know it's the Api Server
            if self.event.kubeservicehost == str(self.event.host):
                self.event = ApiServer()
            else:
                self.event = MetricsServer()
        # if not running as pod.
        else:
            self.classify_using_version_endpoint()

        # in any case, making sure to link previously discovered protocol
        self.event.protocol = discovered_protocol
        # If some check classified the Service,
        # the event will have been replaced.
        return self.event
