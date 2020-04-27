import json
import logging
import requests

from kube_hunter.conf import get_config
from kube_hunter.core.events import handler
from kube_hunter.core.events.types import Event, OpenPortEvent, Service
from kube_hunter.core.types import Discovery

logger = logging.getLogger(__name__)


class KubeDashboardEvent(Service, Event):
    """A web-based Kubernetes user interface allows easy usage with operations on the cluster"""

    def __init__(self, **kargs):
        Service.__init__(self, name="Kubernetes Dashboard", **kargs)


@handler.subscribe(OpenPortEvent, predicate=lambda x: x.port == 30000)
class KubeDashboard(Discovery):
    """K8s Dashboard Discovery
    Checks for the existence of a Dashboard
    """

    def __init__(self, event):
        self.event = event

    @property
    def secure(self):
        config = get_config()
        endpoint = f"http://{self.event.host}:{self.event.port}/api/v1/service/default"
        logger.debug("Attempting to discover an Api server to access dashboard")
        try:
            r = requests.get(endpoint, timeout=config.network_timeout)
            if "listMeta" in r.text and len(json.loads(r.text)["errors"]) == 0:
                return False
        except requests.Timeout:
            logger.debug(f"failed getting {endpoint}", exc_info=True)
        return True

    def execute(self):
        if not self.secure:
            self.publish_event(KubeDashboardEvent())
