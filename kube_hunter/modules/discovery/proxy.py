import logging
import requests

from kube_hunter.conf import get_config
from kube_hunter.core.events import OpenPortEvent
from kube_hunter.core.pubsub.subscription import Event, subscribe
from kube_hunter.core.types import Discovery, Service

logger = logging.getLogger(__name__)


class KubeProxyEvent(Event, Service):
    """proxies from a localhost address to the Kubernetes apiserver"""

    def __init__(self):
        Service.__init__(self, name="Kubernetes Proxy")


@subscribe(OpenPortEvent, predicate=lambda event: event.port == 8001)
class KubeProxy(Discovery):
    """Proxy Discovery
    Checks for the existence of a an open Proxy service
    """

    def __init__(self, event):
        super().__init__(event)
        self.host = event.host
        self.port = event.port or 8001

    @property
    def accesible(self):
        config = get_config()
        endpoint = f"http://{self.host}:{self.port}/api/v1"
        logger.debug("Attempting to discover a proxy service")
        try:
            r = requests.get(endpoint, timeout=config.network_timeout)
            if r.status_code == 200 and "APIResourceList" in r.text:
                return True
        except Exception:
            logger.debug(f"failed to get {endpoint}", exc_info=True)
        return False

    def execute(self):
        if self.accesible:
            yield KubeProxyEvent()
