import json
import logging
import os


import requests

from ...core.events import handler
from ...core.events.types import Vulnerability, Event, OpenPortEvent
from ...core.types import  Hunter, KubernetesCluster, AccessRisk


""" Vulnerabilities """
class secretsAccess(Vulnerability, Event):
    """ Accessing the server API within a compromised pod would help an attacker gain full control over the cluster"""

    def __init__(self, evidence):
        Vulnerability.__init__(self, KubernetesCluster, name="Accessed to pod's secrets", category=AccessRisk)
        self.evidence = evidence

# Passive Hunter
#should change the subscribtion here... (openPortEvent isnt relevant..)
@handler.subscribe(OpenPortEvent, predicate=lambda p: p.port == 6443 or  p.port == 443 or p.port == 10250 or p.port == 10255 or p.port == 2379)
class AccessSecrets(Hunter):
    """Accessing the secrets accessible to the pod"""

    def __init__(self, event):
        self.event = event
        self.secrets_evidence = ''

    def get_services(self):
        logging.debug(self.event.host)
        # get all files and subdirectories files:
        self.secrets_evidence = [val for sublist in [[os.path.join(i[0], j) for j in i[2]] for i in os.walk('./')] for val in sublist]
        if len(self.secrets_evidence) > 0:
            return True
        return False

    #todo:
    # remove traceback
    def execute(self):
        try:
            if self.get_services():
                self.publish_event(secretsAccess(self.secrets_evidence))

        except:
            import traceback
            traceback.print_exc()
