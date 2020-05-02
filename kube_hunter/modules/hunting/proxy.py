import logging
import requests

from enum import Enum
from kube_hunter.conf import get_config
from kube_hunter.core.events import K8sVersionDisclosure
from kube_hunter.core.pubsub.subscription import subscribe
from kube_hunter.core.types import ActiveHunter, Hunter, InformationDisclosure, KubernetesCluster, Vulnerability
from kube_hunter.modules.discovery.dashboard import KubeDashboardEvent
from kube_hunter.modules.discovery.proxy import KubeProxyEvent

logger = logging.getLogger(__name__)


class KubeProxyExposed(Vulnerability):
    """All operations on the cluster are exposed"""

    def __init__(self):
        super().__init__(
            name="Proxy Exposed", component=KubernetesCluster, category=InformationDisclosure, vid="KHV049"
        )


class Service(Enum):
    DASHBOARD = "kubernetes-dashboard"


@subscribe(KubeProxyEvent)
class KubeProxy(Hunter):
    """Proxy Hunting
    Hunts for a dashboard behind the proxy
    """

    def __init__(self, event):
        super().__init__(event)
        self.api_url = f"http://{event.host}:{event.port}/api/v1"

    def execute(self):
        yield KubeProxyExposed()
        for namespace, services in self.services.items():
            for service in services:
                if service == Service.DASHBOARD.value:
                    logger.debug(f"Found a dashboard service in namespace {namespace}")
                    # TODO: check if /proxy is a convention on other services
                    curr_path = f"/api/v1/namespaces/{namespace}/services/{service}/proxy"
                    yield KubeDashboardEvent(path=curr_path, secure=False)

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
        return [item["metadata"]["name"] for item in resource_json["items"]]


@subscribe(KubeProxyExposed)
class ProveProxyExposed(ActiveHunter):
    """Build Date Hunter
    Hunts when proxy is exposed, extracts the build date of kubernetes
    """

    def execute(self):
        config = get_config()
        version_metadata = requests.get(
            f"http://{self.event.host}:{self.event.port}/version", verify=False, timeout=config.network_timeout,
        ).json()
        if "buildDate" in version_metadata:
            self.event.evidence = "build date: {}".format(version_metadata["buildDate"])


@subscribe(KubeProxyExposed)
class K8sVersionDisclosureProve(ActiveHunter):
    """K8s Version Hunter
    Hunts Proxy when exposed, extracts the version
    """

    def execute(self):
        config = get_config()
        version_metadata = requests.get(
            f"http://{self.event.host}:{self.event.port}/version", verify=False, timeout=config.network_timeout,
        ).json()
        if "gitVersion" in version_metadata:
            yield K8sVersionDisclosure(
                version=version_metadata["gitVersion"], from_endpoint="/version", extra_info="on kube-proxy",
            )
