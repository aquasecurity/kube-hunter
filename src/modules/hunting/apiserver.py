import json
import logging

import requests

from ...core.events import handler
from ...core.events.types import Vulnerability, Event, OpenPortEvent
from ...core.types import Hunter, KubernetesCluster, RemoteCodeExec, AccessRisk


""" Vulnerabilities """
class ServerApiAccess(Vulnerability, Event):
    """ Accessing the server API within a compromised pod would help an attacker gain full control over the cluster"""

    def __init__(self, evidence):
        Vulnerability.__init__(self, KubernetesCluster, name="Accessed to server API", category=RemoteCodeExec)
        self.evidence = evidence

class ServiceAccountTokenAccess(Vulnerability, Event):
    """ Accessing the pod's service account token gives an attacker the option to use the server API """

    def __init__(self, evidence):
        Vulnerability.__init__(self, KubernetesCluster, name="Read access to pod's service account token", category=AccessRisk)
        self.evidence = evidence

# Passive Hunter
@handler.subscribe(OpenPortEvent, predicate=lambda x: x.port==443 or x.port==6443)
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
        logging.debug('Passive Hunter is attempting to access the API server using the pod\'s service account token')
        try:
            res = requests.get("https://{host}:{port}/api".format(host=self.event.host, port=self.event.port),
                               headers={'Authorization': 'Bearer ' + self.service_account_token_evidence}, verify=False)
            self.api_server_evidence = res.content
            return res.status_code == 200 and res.content != ''
        except requests.exceptions.ConnectionError:  # e.g. DNS failure, refused connection, etc
            return False

    def get_service_account_token(self):
        logging.debug(self.event.host)
        logging.debug('Passive Hunter is attempting to access pod\'s service account token')
        try:
            with open('/var/run/secrets/kubernetes.io/serviceaccount/token', 'r') as token:
                data = token.read()
                self.service_account_token_evidence = data
                return True
        except IOError:  # Couldn't read file
            return False

    def execute(self):
        if self.get_service_account_token():
            self.publish_event(ServiceAccountTokenAccess(self.service_account_token_evidence))
            if self.access_api_server():
                self.publish_event(ServerApiAccess(self.api_server_evidence))
