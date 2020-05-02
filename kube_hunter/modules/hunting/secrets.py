import logging
import os

from kube_hunter.core.pubsub.subscription import subscribe
from kube_hunter.core.types import AccessRisk, Hunter, KubernetesCluster, Vulnerability
from kube_hunter.modules.discovery.hosts import RunningAsPodEvent

logger = logging.getLogger(__name__)


class ServiceAccountTokenAccess(Vulnerability):
    """ Accessing the pod service account token gives an attacker the option to use the server API """

    def __init__(self, evidence):
        super().__init__(
            name="Read access to pod's service account token",
            component=KubernetesCluster,
            category=AccessRisk,
            vid="KHV050",
            evidence=evidence,
        )


class SecretsAccess(Vulnerability):
    """ Accessing the pod's secrets within a compromised pod might disclose valuable data to a potential attacker"""

    def __init__(self, evidence):
        super().__init__(
            name="Access to pod's secrets", component=KubernetesCluster, category=AccessRisk, evidence=evidence
        )


@subscribe(RunningAsPodEvent)
class AccessSecrets(Hunter):
    """Access Secrets
    Accessing the secrets accessible to the pod"""

    def get_services(self):
        logger.debug("Trying to access pod's secrets directory")
        secrets_evidence = []
        for dirname, _, files in os.walk("/var/run/secrets/"):
            for f in files:
                secrets_evidence.append(os.path.join(dirname, f))
        return secrets_evidence

    def execute(self):
        if self.event.auth_token:
            yield ServiceAccountTokenAccess(self.event.auth_token)
        services = self.get_services()
        if services:
            yield SecretsAccess(services)
