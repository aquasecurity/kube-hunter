import json
import logging

import requests

from ...core.events import handler
from ...core.events.types import Vulnerability, Event, OpenPortEvent
from ...core.types import ActiveHunter, Hunter, KubernetesCluster, InformationDisclosure, RemoteCodeExec, UnauthenticatedAccess, AccessRisk


""" Vulnerabilities """
class ServerApiAccess(Vulnerability, Event):
    """ Accessing the server API within a compromised pod would help an attacker gain full control over the cluster"""

    def __init__(self, evidence):
        Vulnerability.__init__(self, KubernetesCluster, name="Accessed to server API", category=RemoteCodeExec)
        self.evidence = evidence

class ServiceAccountTokenAccess(Vulnerability, Event):
    """ Accessing the pod's service account token gives an attacker the option to use the server API """

    def __init__(self, evidence):
        Vulnerability.__init__(self, KubernetesCluster, name="read access to the token", category=AccessRisk)
        self.evidence = evidence

# Passive Hunter
@handler.subscribe(OpenPortEvent, predicate=lambda p: p.port == 6443)
class AccessApiServerViaServiceAccountToken(Hunter):
    """
    Accessing the api server might grant an attacker full control over the cluster
    """

    def __init__(self, event):
        self.event = event
        self.api_server_evidence = ''
        self.service_account_token_evidence = ''

    def access_api_server(self):
        logging.debug(self.event.host)
        res = requests.get('https://' + str(self.event.host) + ':6443/api', headers={'Authorization': 'Bearer ' + self.service_account_token_evidence},
                     verify=False)
        self.api_server_evidence = res.content
        return res.status_code == 200 and res.content != ''

    def get_service_account_token(self):
        logging.debug(self.event.host)
        with open('/var/run/secrets/kubernetes.io/serviceaccount/token', 'r') as token:
            data = token.read()
            self.service_account_token_evidence = data
        return True

    def execute(self):
        try:
            if self.get_service_account_token():
                self.publish_event(ServiceAccountTokenAccess(self.service_account_token_evidence))
                if self.access_api_server():
                    self.publish_event(ServerApiAccess(self.api_server_evidence))
        except:
            import traceback
            traceback.print_exc()
