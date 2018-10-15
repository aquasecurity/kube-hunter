import json
import logging

import requests

from ...core.events import handler
from ...core.events.types import Vulnerability, Event, OpenPortEvent
from ...core.types import Hunter, KubernetesCluster, RemoteCodeExec, AccessRisk, InformationDisclosure


""" Vulnerabilities """
class ServerApiAccess(Vulnerability, Event):
    """ Accessing the server API within a compromised pod would help an attacker gain full control over the cluster"""

    def __init__(self, evidence):
        Vulnerability.__init__(self, KubernetesCluster, name="Accessed to server API", category=RemoteCodeExec)
        self.evidence = evidence

class ServiceAccountTokenAccess(Vulnerability, Event):
    """ Accessing the pod's service account token gives an attacker the option to use the server API """

    def __init__(self, evidence):
        Vulnerability.__init__(self, KubernetesCluster, name="Read access to pod's service account token",
                               category=AccessRisk)
        self.evidence = evidence

class podListAccessDefaultNamespace(Vulnerability, Event):
    """ Accessing the pods list under default namespace within a compromised pod might grant an attacker a valuable
     information to harm the cluster """

    def __init__(self, evidence):
        Vulnerability.__init__(self, KubernetesCluster, name="Access to the pods list under default namespace",
                               category=InformationDisclosure)
        self.evidence = evidence

class podListAccessAllNamespaces(Vulnerability, Event):
    """ Accessing the pods list under ALL of the namespaces within a compromised pod might grant an attacker a valuable
     information to harm the cluster """

    def __init__(self, evidence):
        Vulnerability.__init__(self, KubernetesCluster, name="Access to the pods list under ALL namespaces",
                               category=InformationDisclosure)
        self.evidence = evidence


# Passive Hunter
@handler.subscribe(OpenPortEvent, predicate=lambda x: x.port == 443 or x.port == 6443)
class AccessApiServerViaServiceAccountToken(Hunter):
    """
    Accessing the api server might grant an attacker full control over the cluster
    """

    def __init__(self, event):
        self.event = event
        self.api_server_evidence = ''
        self.service_account_token_evidence = ''
        self.pod_list_under_default_namespace_evidence = ''
        self.pod_list_under_all_namespaces_evidence = ''

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

    def get_pods_list_under_default_namespace(self):
        logging.debug(self.event.host)
        logging.debug('Passive Hunter is attempting to list pods under default '
                      'namespace using the pod\'s service account token')
        try:
            res = requests.get("https://{host}:{port}/api/v1/namespaces/{namespace}/pods".format(host=self.event.host,
                                port=self.event.port, namespace='default'),
                               headers={'Authorization': 'Bearer ' + self.service_account_token_evidence}, verify=False)
            self.pod_list_under_default_namespace_evidence = res.content
            return res.status_code == 200 and res.content != ''
        except requests.exceptions.ConnectionError:  # e.g. DNS failure, refused connection, etc
            return False

    def get_pods_list_under_all_namespace(self):
        logging.debug(self.event.host)
        logging.debug('Passive Hunter is attempting to list pods under default '
                      'namespace using the pod\'s service account token')
        try:
            res = requests.get("https://{host}:{port}/api/v1/pods".format(host=self.event.host, port=self.event.port),
                               headers={'Authorization': 'Bearer ' + self.service_account_token_evidence}, verify=False)
            self.pod_list_under_all_namespaces_evidence = res.content
            return res.status_code == 200 and res.content != ''
        except requests.exceptions.ConnectionError:  # e.g. DNS failure, refused connection, etc
            return False

    def execute(self):
        if self.get_service_account_token():
            self.publish_event(ServiceAccountTokenAccess(self.service_account_token_evidence))
            if self.access_api_server():
                self.publish_event(ServerApiAccess(self.api_server_evidence))
            if self.get_pods_list_under_all_namespace():
                self.publish_event(podListAccessAllNamespaces(self.pod_list_under_all_namespaces_evidence))
            if self.get_pods_list_under_default_namespace():
                self.publish_event(podListAccessDefaultNamespace(self.pod_list_under_default_namespace_evidence))


