import logging
import requests

from typing import Optional
from kube_hunter.conf import get_config
from kube_hunter.core.pubsub.subscription import Event
from kube_hunter.core.types import InformationDisclosure, KubernetesCluster, Vulnerability

logger = logging.getLogger(__name__)


class NewHostEvent(Event):
    host: str
    cloud_type: str

    def __init__(self, host: str, cloud: Optional[str] = None):
        super().__init__()
        self.host = host
        self.cloud_type = cloud or ""

    @property
    def cloud(self):
        if not self.cloud_type:
            self.cloud_type = self.get_cloud()
        return self.cloud_type

    def get_cloud(self):
        config = get_config()
        try:
            logger.debug(f"Check cloud provider of IP address {self.host}")
            result = requests.get(
                f"https://api.azurespeed.com/api/region?ipOrUrl={self.host}", timeout=config.network_timeout,
            ).json()
            return result["cloud"] or "NoCloud"
        except requests.ConnectionError:
            logger.info(f"Failed to connect cloud type service", exc_info=True)
        except Exception:
            logger.warning(f"Unable to check cloud of {self.host}", exc_info=True)
        return "NoCloud"

    def __str__(self):
        return str(self.host)

    def location(self):
        return str(self)


class OpenPortEvent(Event):
    host: str
    port: int

    def __init__(self, host: str, port: int):
        super().__init__()
        self.host = host
        self.port = port

    def __str__(self):
        return f"{self.host}:{self.port}"

    def location(self):
        return str(self)


class HuntStarted(Event):
    pass


class HuntFinished(Event):
    pass


class ReportDispatched(Event):
    pass


class K8sVersionDisclosure(Vulnerability):
    version: str
    from_endpoint: str
    extra_info: str

    def __init__(self, version: str, from_endpoint: str, extra_info=""):
        super().__init__(
            name="K8s Version Disclosure",
            component=KubernetesCluster,
            category=InformationDisclosure,
            vid="KHV002",
            evidence=version,
            description=f"The kubernetes version could be obtained from the {from_endpoint} endpoint {extra_info}",
        )
        self.version = version
        self.from_endpoint = from_endpoint
        self.extra_info = extra_info
