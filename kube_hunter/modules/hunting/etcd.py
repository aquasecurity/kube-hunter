import logging
import requests

from kube_hunter.conf import get_config
from kube_hunter.core.events import handler
from kube_hunter.core.events.types import Vulnerability, Event, OpenPortEvent
from kube_hunter.core.types import (
    ActiveHunter,
    Hunter,
    KubernetesCluster,
    InformationDisclosure,
    RemoteCodeExec,
    UnauthenticatedAccess,
    AccessRisk,
)

logger = logging.getLogger(__name__)
ETCD_PORT = 2379


""" Vulnerabilities """


class EtcdRemoteWriteAccessEvent(Vulnerability, Event):
    """Remote write access might grant an attacker full control over the kubernetes cluster"""

    def __init__(self, write_res):
        Vulnerability.__init__(
            self,
            KubernetesCluster,
            name="Etcd Remote Write Access Event",
            category=RemoteCodeExec,
            vid="KHV031",
        )
        self.evidence = write_res


class EtcdRemoteReadAccessEvent(Vulnerability, Event):
    """Remote read access might expose to an attacker cluster's possible exploits, secrets and more."""

    def __init__(self, keys):
        Vulnerability.__init__(
            self,
            KubernetesCluster,
            name="Etcd Remote Read Access Event",
            category=AccessRisk,
            vid="KHV032",
        )
        self.evidence = keys


class EtcdRemoteVersionDisclosureEvent(Vulnerability, Event):
    """Remote version disclosure might give an attacker a valuable data to attack a cluster"""

    def __init__(self, version):

        Vulnerability.__init__(
            self,
            KubernetesCluster,
            name="Etcd Remote version disclosure",
            category=InformationDisclosure,
            vid="KHV033",
        )
        self.evidence = version


class EtcdAccessEnabledWithoutAuthEvent(Vulnerability, Event):
    """Etcd is accessible using HTTP (without authorization and authentication),
    it would allow a potential attacker to
     gain access to the etcd"""

    def __init__(self, version):
        Vulnerability.__init__(
            self,
            KubernetesCluster,
            name="Etcd is accessible using insecure connection (HTTP)",
            category=UnauthenticatedAccess,
            vid="KHV034",
        )
        self.evidence = version


# Active Hunter
@handler.subscribe(OpenPortEvent, predicate=lambda p: p.port == ETCD_PORT)
class EtcdRemoteAccessActive(ActiveHunter):
    """Etcd Remote Access
    Checks for remote write access to etcd, will attempt to add a new key to the etcd DB"""

    def __init__(self, event):
        self.event = event
        self.write_evidence = ""
        self.event.protocol = "https"

    def db_keys_write_access(self):
        config = get_config()
        logger.debug(f"Trying to write keys remotely on host {self.event.host}")
        data = {"value": "remotely written data"}
        try:
            r = requests.post(
                f"{self.event.protocol}://{self.event.host}:{ETCD_PORT}/v2/keys/message",
                data=data,
                timeout=config.network_timeout,
            )
            self.write_evidence = r.content if r.status_code == 200 and r.content else False
            return self.write_evidence
        except requests.exceptions.ConnectionError:
            return False

    def execute(self):
        if self.db_keys_write_access():
            self.publish_event(EtcdRemoteWriteAccessEvent(self.write_evidence))


# Passive Hunter
@handler.subscribe(OpenPortEvent, predicate=lambda p: p.port == ETCD_PORT)
class EtcdRemoteAccess(Hunter):
    """Etcd Remote Access
    Checks for remote availability of etcd, its version, and read access to the DB
    """

    def __init__(self, event):
        self.event = event
        self.version_evidence = ""
        self.keys_evidence = ""
        self.event.protocol = "https"

    def db_keys_disclosure(self):
        config = get_config()
        logger.debug(f"{self.event.host} Passive hunter is attempting to read etcd keys remotely")
        try:
            r = requests.get(
                f"{self.event.protocol}://{self.event.host}:{ETCD_PORT}/v2/keys",
                verify=False,
                timeout=config.network_timeout,
            )
            self.keys_evidence = r.content if r.status_code == 200 and r.content != "" else False
            return self.keys_evidence
        except requests.exceptions.ConnectionError:
            return False

    def version_disclosure(self):
        config = get_config()
        logger.debug(f"Trying to check etcd version remotely at {self.event.host}")
        try:
            r = requests.get(
                f"{self.event.protocol}://{self.event.host}:{ETCD_PORT}/version",
                verify=False,
                timeout=config.network_timeout,
            )
            self.version_evidence = r.content if r.status_code == 200 and r.content else False
            return self.version_evidence
        except requests.exceptions.ConnectionError:
            return False

    def insecure_access(self):
        config = get_config()
        logger.debug(f"Trying to access etcd insecurely at {self.event.host}")
        try:
            r = requests.get(
                f"http://{self.event.host}:{ETCD_PORT}/version",
                verify=False,
                timeout=config.network_timeout,
            )
            return r.content if r.status_code == 200 and r.content else False
        except requests.exceptions.ConnectionError:
            return False

    def execute(self):
        if self.insecure_access():  # make a decision between http and https protocol
            self.event.protocol = "http"
        if self.version_disclosure():
            self.publish_event(EtcdRemoteVersionDisclosureEvent(self.version_evidence))
            if self.event.protocol == "http":
                self.publish_event(EtcdAccessEnabledWithoutAuthEvent(self.version_evidence))
            if self.db_keys_disclosure():
                self.publish_event(EtcdRemoteReadAccessEvent(self.keys_evidence))
