import logging
import requests

from kube_hunter.conf import get_config
from kube_hunter.core.events import OpenPortEvent
from kube_hunter.core.pubsub.subscription import subscribe
from kube_hunter.core.types import (
    AccessRisk,
    ActiveHunter,
    Hunter,
    InformationDisclosure,
    KubernetesCluster,
    RemoteCodeExec,
    UnauthenticatedAccess,
    Vulnerability,
)

logger = logging.getLogger(__name__)
ETCD_PORT = 2379


class EtcdRemoteWriteAccessEvent(Vulnerability):
    """Remote write access might grant an attacker full control over the kubernetes cluster"""

    def __init__(self, write_response: str):
        super().__init__(
            name="Etcd Remote Write Access Event",
            component=KubernetesCluster,
            category=RemoteCodeExec,
            vid="KHV031",
            evidence=write_response,
        )


class EtcdRemoteReadAccess(Vulnerability):
    """Remote read access might expose to an attacker cluster's possible exploits, secrets and more"""

    def __init__(self, keys):
        super().__init__(
            name="Etcd Remote Read Access",
            component=KubernetesCluster,
            category=AccessRisk,
            vid="KHV032",
            evidence=keys,
        )


class EtcdRemoteVersionDisclosure(Vulnerability):
    """Remote version disclosure might give an attacker a valuable data to attack a cluster"""

    def __init__(self, version: str):
        super().__init__(
            name="Etcd Remote version disclosure",
            component=KubernetesCluster,
            category=InformationDisclosure,
            vid="KHV033",
            evidence=version,
        )


class EtcdAccessEnabledWithoutAuth(Vulnerability):
    """Etcd is accessible using HTTP (without authorization and authentication),
    it would allow a potential attacker to gain access to the store cluster data"""

    def __init__(self, version: str):
        super().__init__(
            name="Etcd is accessible using insecure connection (HTTP)",
            component=KubernetesCluster,
            category=UnauthenticatedAccess,
            vid="KHV034",
            evidence=version,
        )


@subscribe(OpenPortEvent, predicate=lambda event: event.port == ETCD_PORT)
class EtcdRemoteAccessActive(ActiveHunter):
    """Etcd Remote Access
    Checks for remote write access to etcd, will attempt to add a new key"""

    def db_keys_write_access(self):
        config = get_config()
        logger.debug(f"Trying to write keys remotely on etcd host {self.event.host}")
        data = {"value": "remotely written data"}
        try:
            response = requests.post(
                f"https://{self.event.host}:{ETCD_PORT}/v2/keys/message", data=data, timeout=config.network_timeout,
            )
            response.raise_for_status()
            return response.text
        except Exception:
            logger.debug(f"Failed to write keys to {self.event.host}", exc_info=True)
            return None

    def execute(self):
        response = self.db_keys_write_access()
        if response:
            yield EtcdRemoteWriteAccessEvent(response)


@subscribe(OpenPortEvent, predicate=lambda event: event.port == ETCD_PORT)
class EtcdRemoteAccess(Hunter):
    """Etcd Remote Access
    Checks for remote read access to etcd
    """

    def __init__(self, event: OpenPortEvent):
        super().__init__(event)
        self.protocol = "https"

    def db_keys_disclosure(self):
        config = get_config()
        logger.debug(f"Trying attempting to read etcd keys from {self.event.host}")
        try:
            endpoint = f"{self.protocol}://{self.event.host}:{ETCD_PORT}/v2/keys"
            response = requests.get(endpoint, verify=False, timeout=config.network_timeout)
            response.raise_for_status()
            return response.content
        except Exception:
            logger.debug(f"Failed to read keys from {self.event.host}", exc_info=True)
            return None

    def version_disclosure(self):
        config = get_config()
        logger.debug(f"Trying to check etcd version remotely of {self.event.host}")
        try:
            endpint = f"{self.protocol}://{self.event.host}:{ETCD_PORT}/version"
            response = requests.get(endpint, verify=False, timeout=config.network_timeout)
            response.raise_for_status()
            return response.content
        except Exception:
            logger.debug(f"Failed to get etcd version of {self.event.host}", exc_info=True)
            return None

    def insecure_access(self):
        config = get_config()
        logger.debug(f"Trying to access etcd insecurely at {self.event.host}")
        try:
            endpoint = f"http://{self.event.host}:{ETCD_PORT}/version"
            response = requests.get(endpoint, verify=False, timeout=config.network_timeout)
            response.raise_for_status()
            return response.content
        except Exception:
            logger.debug(f"Failed to insecurely get etcd version of {self.event.host}", exc_info=True)
            return None

    def execute(self):
        if self.insecure_access():
            self.protocol = "http"
        version = self.version_disclosure()
        if version:
            yield EtcdRemoteVersionDisclosure(version)
            if self.protocol == "http":
                yield EtcdAccessEnabledWithoutAuth(version)
            keys = self.db_keys_disclosure()
            if keys:
                yield EtcdRemoteReadAccess(keys)
