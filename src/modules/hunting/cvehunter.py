import logging
import json
import requests
import uuid
import ast

from ...core.events import handler
from ...core.events.types import Vulnerability, Event
from ..discovery.apiserver import ApiServer
from ...core.types import Hunter, ActiveHunter, KubernetesCluster, RemoteCodeExec, AccessRisk, InformationDisclosure, \
    PrivilegeEscalation, DenialOfService

""" Vulnerabilities """


class ServerApiVersionEndPointAccessPE(Vulnerability, Event):
    """Node is vulnerable to critical CVE-2018-1002105"""

    def __init__(self, evidence):
        Vulnerability.__init__(self, KubernetesCluster, name="Critical Privilege Escalation CVE", category=PrivilegeEscalation)
        self.evidence = evidence


class ServerApiVersionEndPointAccessDos(Vulnerability, Event):
    """Users that are authorized to make patch requests to the Kubernetes API Server can send a specially crafted patch of type json-patch that consumes excessive resources while processing, causing a Denial of Service on the API Server. CVE-2019-1002100"""

    def __init__(self, evidence):
        Vulnerability.__init__(self, KubernetesCluster, name="Denial of Service to Kubernetes API Server", category=DenialOfService)
        self.evidence = evidence


# Passive Hunter
@handler.subscribe(ApiServer)
class IsVulnerableToCVEAttack(Hunter):
    """ Node is running a Kubernetes version vulnerable to critical CVE-2018-1002105 """

    def __init__(self, event):
        self.event = event
        self.headers = dict()
        self.path = "https://{}:{}".format(self.event.host, self.event.port)
        self.service_account_token_evidence = ''
        self.api_server_evidence = ''
        self.k8sVersion = ''

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

    def get_api_server_version_end_point(self):
        logging.debug(self.event.host)
        logging.debug('Passive Hunter is attempting to access the API server version end point using the pod\'s service account token')
        try:
            res = requests.get("{path}/version".format(path=self.path),
                               headers=self.headers, verify=False)
            self.api_server_evidence = res.content
            resDict = ast.literal_eval(res.content)
            version = resDict["gitVersion"].split('.')
            first_two_minor_digits = eval(version[1])
            last_two_minor_digits = eval(version[2])
            return [first_two_minor_digits, last_two_minor_digits]

        except (requests.exceptions.ConnectionError, KeyError):
            return None

    def check_cve_2018_1002105(self, api_version):
        first_two_minor_digists = api_version[0]
        last_two_minor_digists = api_version[1]

        if first_two_minor_digists == 10 and last_two_minor_digists < 11:
            return True
        elif first_two_minor_digists == 11 and last_two_minor_digists < 5:
            return True
        elif first_two_minor_digists == 12 and last_two_minor_digists < 3:
            return True
        elif first_two_minor_digists < 10:
            return True

        return False

    def check_cve_2019_1002100(self, api_version):
        """
        Kubernetes v1.0.x-1.10.x
        Kubernetes v1.11.0-1.11.7 (fixed in v1.11.8)
        Kubernetes v1.12.0-1.12.5 (fixed in v1.12.6)
        Kubernetes v1.13.0-1.13.3 (fixed in v1.13.4)
        """

        first_two_minor_digists = api_version[0]
        last_two_minor_digists = api_version[1]

        if first_two_minor_digists == 11 and last_two_minor_digists < 8:
            return True
        elif first_two_minor_digists == 12 and last_two_minor_digists < 6:
            return True
        elif first_two_minor_digists == 13 and last_two_minor_digists < 4:
            return True
        elif first_two_minor_digists < 11:
            return True

        return False

    def execute(self):
        self.get_service_account_token()  # From within a Pod we may have extra credentials
        api_version = self.get_api_server_version_end_point()

        if api_version:
            if self.check_cve_2018_1002105(api_version):
                self.publish_event(ServerApiVersionEndPointAccessPE(self.api_server_evidence))

            if self.check_cve_2019_1002100(api_version):
                self.publish_event(ServerApiVersionEndPointAccessDos(self.api_server_evidence))


