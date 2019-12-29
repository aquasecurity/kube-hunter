import json
import logging
import os
import requests

from kube_hunter.core.events import handler
from kube_hunter.core.events.types import Vulnerability, Event
from kube_hunter.core.types import Hunter, KubernetesCluster, AccessRisk
from kube_hunter.modules.discovery.hosts import RunningAsPodEvent


class ServiceAccountTokenAccess(Vulnerability, Event):
    """ Accessing the pod service account token gives an attacker the option to use the server API """

    def __init__(self, evidence):
        Vulnerability.__init__(self, KubernetesCluster, name="Read access to pod's service account token",
                               category=AccessRisk, vid="KHV050")
        self.evidence = evidence

class SecretsAccess(Vulnerability, Event):
    """ Accessing the pod's secrets within a compromised pod might disclose valuable data to a potential attacker"""

    def __init__(self, evidence):
        Vulnerability.__init__(self, KubernetesCluster, name="Access to pod's secrets", category=AccessRisk)
        self.evidence = evidence


# Passive Hunter
@handler.subscribe(RunningAsPodEvent)
class AccessSecrets(Hunter):
    """Access Secrets
    Accessing the secrets accessible to the pod"""

    def __init__(self, event):
        self.event = event
        self.secrets_evidence = ''

    def get_services(self):
        logging.debug(self.event.host)
        logging.debug('Passive Hunter is attempting to access pod\'s secrets directory')
        # get all files and subdirectories files:
        self.secrets_evidence = [val for sublist in [[os.path.join(i[0], j) for j in i[2]] for i in os.walk('/var/run/secrets/')] for val in sublist]
        return True if (len(self.secrets_evidence) > 0) else False

    def execute(self):
        if self.event.auth_token is not None:
            self.publish_event(ServiceAccountTokenAccess(self.event.auth_token))
        if self.get_services():
            self.publish_event(SecretsAccess(self.secrets_evidence))
