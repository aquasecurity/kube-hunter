import logging
import os

from kube_hunter.core.events import handler
from kube_hunter.core.events.types import Vulnerability, Event
from kube_hunter.core.types import Hunter, KubernetesCluster, AccessRisk
from kube_hunter.modules.discovery.hosts import RunningAsPodEvent

logger = logging.getLogger(__name__)


class ServiceAccountTokenAccess(Vulnerability, Event):
    """Accessing the pod service account token gives an attacker the option to use the server API"""

    def __init__(self, evidence):
        Vulnerability.__init__(
            self,
            KubernetesCluster,
            name="Read access to pod's service account token",
            category=AccessRisk,
            vid="KHV050",
        )
        self.evidence = evidence


class SecretsAccess(Vulnerability, Event):
    """Accessing the pod's secrets within a compromised pod might disclose valuable data to a potential attacker"""

    def __init__(self, evidence):
        Vulnerability.__init__(
            self,
            component=KubernetesCluster,
            name="Access to pod's secrets",
            category=AccessRisk,
        )
        self.evidence = evidence


# Passive Hunter
@handler.subscribe(RunningAsPodEvent)
class AccessSecrets(Hunter):
    """Access Secrets
    Accessing the secrets accessible to the pod"""

    def __init__(self, event):
        self.event = event
        self.secrets_evidence = ""

    def get_services(self):
        logger.debug("Trying to access pod's secrets directory")
        # get all files and subdirectories files:
        self.secrets_evidence = []
        for dirname, _, files in os.walk("/var/run/secrets/"):
            for f in files:
                self.secrets_evidence.append(os.path.join(dirname, f))
        return len(self.secrets_evidence) > 0

    def execute(self):
        if self.event.auth_token is not None:
            self.publish_event(ServiceAccountTokenAccess(self.event.auth_token))
        if self.get_services():
            self.publish_event(SecretsAccess(self.secrets_evidence))
