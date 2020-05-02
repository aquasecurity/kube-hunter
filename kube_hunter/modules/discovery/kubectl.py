import logging
import subprocess

from kube_hunter.core.types import Discovery
from kube_hunter.core.events import HuntStarted
from kube_hunter.core.pubsub.subscription import Event, subscribe

logger = logging.getLogger(__name__)


class KubectlClientFound(Event):
    """The API server is in charge of all operations on the cluster."""

    def __init__(self, version):
        super().__init__()
        self.version = version

    def location(self):
        return "local machine"


@subscribe(HuntStarted)
class KubectlClientDiscovery(Discovery):
    """Kubectl Client Discovery
    Checks for the existence of a local kubectl client
    """

    def get_kubectl_binary_version(self):
        version = None
        try:
            # kubectl version --client does not make any connection to the cluster/internet whatsoever.
            version_info = subprocess.check_output("kubectl version --client", stderr=subprocess.STDOUT)
            if b"GitVersion" in version_info:
                # extracting version from kubectl output
                version_info = version_info.decode()
                start = version_info.find("GitVersion")
                version = version_info[start + len("GitVersion':\"") : version_info.find('",', start)]
        except Exception:
            logger.debug("Could not find kubectl client")
        return version

    def execute(self):
        logger.debug("Attempting to discover a local kubectl client")
        version = self.get_kubectl_binary_version()
        if version:
            yield KubectlClientFound(version=version)
