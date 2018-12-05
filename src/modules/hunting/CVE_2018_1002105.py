import logging
import json
import requests
import uuid
import ast

from ...core.events import handler
from ...core.events.types import Vulnerability, Event, OpenPortEvent
from ...core.types import Hunter, ActiveHunter, KubernetesCluster, RemoteCodeExec, AccessRisk, InformationDisclosure, PrivilegeEscalation

""" Vulnerabilities """
class ServerApiVersionEndPointAccess(Vulnerability, Event):
    """ Accessing the server API within a compromised pod would help an attacker gain full control over the cluster"""

    def __init__(self, evidence):
        Vulnerability.__init__(self, KubernetesCluster, name="Critical PrivilegedEscalation CVE", category=PrivilegeEscalation)
        self.evidence = evidence

# Passive Hunter
@handler.subscribe(OpenPortEvent, predicate=lambda x: x.port == 443 or x.port == 6443)
class IsVulnerableToCVEAttack(Hunter):
    """ CVE-2018-1002105
    Pod is vulnerable to critical CVE-2018-1002105
    """

    def __init__(self, event):
        self.event = event
        self.headers = dict()
        self.path = "https://{}:{}".format(self.event.host, self.event.port)
        self.service_account_token_evidence = ''
        self.api_server_evidence = ''
        self.k8sVersion = ''

    def access_api_server_version_end_point(self):
        logging.debug(self.event.host)
        logging.debug('Passive Hunter is attempting to access the API server /version end point using the pod\'s service account token')
        try:
            res = requests.get("{path}/version".format(path=self.path),
                               headers=self.headers, verify=False)
            self.api_server_evidence = res.content
            resDict = ast.literal_eval(res.content)
            version = resDict["gitVersion"].split('.')
            first_two_minor_digists = eval(version[1])
            last_two_minor_digists = eval(version[2])

            if first_two_minor_digists == 10 and last_two_minor_digists < 11:
                return True
            elif first_two_minor_digists == 11 and last_two_minor_digists < 5:
                return True
            elif first_two_minor_digists == 12 and last_two_minor_digists < 3:
                return True
            elif first_two_minor_digists < 10:
                return True
        except (requests.exceptions.ConnectionError, KeyError):
            return False

    def get_service_account_token(self):
        logging.debug(self.event.host)
        logging.debug('Passive Hunter is attempting to access pod\'s service account token')
        try:
            with open('/var/run/secrets/kubernetes.io/serviceaccount/token', 'r') as token:
                data = token.read()
                self.service_account_token_evidence = data
                self.headers = {'Authorization': 'Bearer ' + self.service_account_token_evidence}
                return True
        except IOError:  # Couldn't read file
            return False

    def execute(self):
        if self.get_service_account_token():  # From within a Pod
            if self.access_api_server_version_end_point():
                self.publish_event(ServerApiVersionEndPointAccess(self.api_server_evidence))
        else:
            self.publish_event(ServerApiVersionEndPointAccess(self.api_server_evidence))

