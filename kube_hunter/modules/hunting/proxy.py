import logging
import requests

from enum import Enum

from kube_hunter.conf import get_config
from kube_hunter.core.events import handler
from kube_hunter.core.events.types import Event, Vulnerability, K8sVersionDisclosure
from kube_hunter.core.types import (
    ActiveHunter,
    Hunter,
    KubernetesCluster,
    InformationDisclosure,
)
from kube_hunter.modules.discovery.dashboard import KubeDashboardEvent
from kube_hunter.modules.discovery.proxy import KubeProxyEvent

logger = logging.getLogger(__name__)


class KubeProxyExposed(Vulnerability, Event):
    """All operations on the cluster are exposed"""

    def __init__(self):
        Vulnerability.__init__(
            self,
            KubernetesCluster,
            "Proxy Exposed",
            category=InformationDisclosure,
            vid="KHV049",
        )


class Service(Enum):
    DASHBOARD = "kubernetes-dashboard"


@handler.subscribe(KubeProxyEvent)
class KubeProxy(Hunter):
    """Proxy Hunting
    Hunts for a dashboard behind the proxy
    """

    def __init__(self, event):
        self.event = event
        self.api_url = f"http://{self.event.host}:{self.event.port}/api/v1"

    def execute(self):
        self.publish_event(KubeProxyExposed())
        for namespace, services in self.services.items():
            for service in services:
                if service == Service.DASHBOARD.value:
                    logger.debug(f"Found a dashboard service '{service}'")
                    # TODO: check if /proxy is a convention on other services
                    curr_path = f"api/v1/namespaces/{namespace}/services/{service}/proxy"
                    self.publish_event(KubeDashboardEvent(path=curr_path, secure=False))

    @property
    def namespaces(self):
        config = get_config()
        resource_json = requests.get(f"{self.api_url}/namespaces", timeout=config.network_timeout).json()
        return self.extract_names(resource_json)

    @property
    def services(self):
        config = get_config()
        # map between namespaces and service names
        services = dict()
        for namespace in self.namespaces:
            resource_path = f"{self.api_url}/namespaces/{namespace}/services"
            resource_json = requests.get(resource_path, timeout=config.network_timeout).json()
            services[namespace] = self.extract_names(resource_json)
        logger.debug(f"Enumerated services [{' '.join(services)}]")
        return services

    @staticmethod
    def extract_names(resource_json):
        names = list()
        for item in resource_json["items"]:
            names.append(item["metadata"]["name"])
        return names


@handler.subscribe(KubeProxyExposed)
class ProveProxyExposed(ActiveHunter):
    """Build Date Hunter
    Hunts when proxy is exposed, extracts the build date of kubernetes
    """

    def __init__(self, event):
        self.event = event

    def execute(self):
        config = get_config()
        version_metadata = requests.get(
            f"http://{self.event.host}:{self.event.port}/version",
            verify=False,
            timeout=config.network_timeout,
        ).json()
        if "buildDate" in version_metadata:
            self.event.evidence = "build date: {}".format(version_metadata["buildDate"])


@handler.subscribe(KubeProxyExposed)
class K8sVersionDisclosureProve(ActiveHunter):
    """K8s Version Hunter
    Hunts Proxy when exposed, extracts the version
    """

    def __init__(self, event):
        self.event = event

    def execute(self):
        config = get_config()
        version_metadata = requests.get(
            f"http://{self.event.host}:{self.event.port}/version",
            verify=False,
            timeout=config.network_timeout,
        ).json()
        if "gitVersion" in version_metadata:
            self.publish_event(
                K8sVersionDisclosure(
                    version=version_metadata["gitVersion"],
                    from_endpoint="/version",
                    extra_info="on kube-proxy",
                )
            )
