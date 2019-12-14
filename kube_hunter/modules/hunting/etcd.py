import logging

import requests

from kube_hunter.core.events import handler
from kube_hunter.core.events.types import Vulnerability, Event, OpenPortEvent
from kube_hunter.core.types import ActiveHunter, Hunter, KubernetesCluster, \
    InformationDisclosure, RemoteCodeExec, UnauthenticatedAccess, AccessRisk


""" Vulnerabilities """
class EtcdRemoteWriteAccessEvent(Vulnerability, Event):
    """Remote write access might grant an attacker full control over the kubernetes cluster"""

    def __init__(self, write_res):
        Vulnerability.__init__(self, KubernetesCluster, name="Etcd Remote Write Access Event", category=RemoteCodeExec, vid="KHV031")
        self.evidence = write_res


class EtcdRemoteReadAccessEvent(Vulnerability, Event):
    """Remote read access might expose to an attacker cluster's possible exploits, secrets and more."""

    def __init__(self, keys):
        Vulnerability.__init__(self, KubernetesCluster,  name="Etcd Remote Read Access Event", category=AccessRisk, vid="KHV032")
        self.evidence = keys


class EtcdRemoteVersionDisclosureEvent(Vulnerability, Event):
    """Remote version disclosure might give an attacker a valuable data to attack a cluster"""

    def __init__(self, version):

        Vulnerability.__init__(self, KubernetesCluster, name="Etcd Remote version disclosure",
                               category=InformationDisclosure, vid="KHV033")
        self.evidence = version


class EtcdAccessEnabledWithoutAuthEvent(Vulnerability, Event):
    """Etcd is accessible using HTTP (without authorization and authentication), it would allow a potential attacker to
     gain access to the etcd"""

    def __init__(self, version):
        Vulnerability.__init__(self, KubernetesCluster,  name="Etcd is accessible using insecure connection (HTTP)",
                               category=UnauthenticatedAccess, vid="KHV034")
        self.evidence = version


# Active Hunter
@handler.subscribe(OpenPortEvent, predicate=lambda p: p.port == 2379)
class EtcdRemoteAccessActive(ActiveHunter):
    """Etcd Remote Access
    Checks for remote write access to etcd- will attempt to add a new key to the etcd DB"""

    def __init__(self, event):
        self.event = event
        self.write_evidence = ''

    def db_keys_write_access(self):
        logging.debug("Active hunter is attempting to write keys remotely on host " + self.event.host)
        data = {
            'value': 'remotely written data'
        }
        try:
            r = requests.post("{protocol}://{host}:{port}/v2/keys/message".format(host=self.event.host, port=2379,
                                                                                  protocol=self.protocol), data=data)
            self.write_evidence = r.content if r.status_code == 200 and r.content != '' else False
            return self.write_evidence
        except requests.exceptions.ConnectionError:
            return False

    def execute(self):
        if self.db_keys_write_access():
            self.publish_event(EtcdRemoteWriteAccessEvent(self.write_evidence))


# Passive Hunter
@handler.subscribe(OpenPortEvent, predicate=lambda p: p.port == 2379)
class EtcdRemoteAccess(Hunter):
    """Etcd Remote Access
    Checks for remote availability of etcd, its version, and read access to the DB
    """

    def __init__(self, event):
        self.event = event
        self.version_evidence = ''
        self.keys_evidence = ''
        self.protocol = 'https'

    def db_keys_disclosure(self):
        logging.debug(self.event.host + " Passive hunter is attempting to read etcd keys remotely")
        try:
            r = requests.get(
                "{protocol}://{host}:{port}/v2/keys".format(protocol=self.protocol, host=self.event.host, port=2379),
                verify=False)
            self.keys_evidence = r.content if r.status_code == 200 and r.content != '' else False
            return self.keys_evidence
        except requests.exceptions.ConnectionError:
            return False

    def version_disclosure(self):
        logging.debug(self.event.host + " Passive hunter is attempting to check etcd version remotely")
        try:
            r = requests.get(
                "{protocol}://{host}:{port}/version".format(protocol=self.protocol, host=self.event.host, port=2379),
                verify=False)
            self.version_evidence = r.content if r.status_code == 200 and r.content != '' else False
            return self.version_evidence
        except requests.exceptions.ConnectionError:
            return False

    def insecure_access(self):
        logging.debug(self.event.host + " Passive hunter is attempting to access etcd insecurely")
        try:
            r = requests.get("http://{host}:{port}/version".format(host=self.event.host, port=2379), verify=False)
            return r.content if r.status_code == 200 and r.content != '' else False
        except requests.exceptions.ConnectionError:
            return False

    def execute(self):
        if self.insecure_access():  # make a decision between http and https protocol
            self.protocol = 'http'
        if self.version_disclosure():
            self.publish_event(EtcdRemoteVersionDisclosureEvent(self.version_evidence))
            if self.protocol == 'http':
                self.publish_event(EtcdAccessEnabledWithoutAuthEvent(self.version_evidence))
            if self.db_keys_disclosure():
                self.publish_event(EtcdRemoteReadAccessEvent(self.keys_evidence))
