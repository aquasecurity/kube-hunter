import logging
import requests

from kube_hunter.conf import get_config
from kube_hunter.core.events import OpenPortEvent
from kube_hunter.core.pubsub.subscription import Event, subscribe
from kube_hunter.core.types import Discovery, Service

logger = logging.getLogger(__name__)


class KubeDashboardEvent(Service, Event):
    """A web-based Kubernetes user interface allows easy usage with operations on the cluster"""

    def __init__(self, **kargs):
        Service.__init__(self, name="Kubernetes Dashboard", **kargs)


@subscribe(OpenPortEvent, predicate=lambda event: event.port == 30000)
class KubeDashboard(Discovery):
    """K8s Dashboard Discovery
    Checks for the existence of a Dashboard
    """

    @property
    def secure(self):
        config = get_config()
        endpoint = f"http://{self.event.host}:{self.event.port}/api/v1/service/default"
        logger.debug("Attempting to discover an Api server to access dashboard")
        try:
            r = requests.get(endpoint, timeout=config.network_timeout)
            if "listMeta" in r.text and not r.json()["errors"]:
                return False
        except requests.Timeout:
            logger.debug(f"failed getting {endpoint}", exc_info=True)
        return True

    def execute(self):
        if not self.secure:
            yield KubeDashboardEvent()
