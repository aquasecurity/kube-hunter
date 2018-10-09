import json
import logging

import requests

from ...core.events import handler
from ...core.events.types import Vulnerability, Event, OpenPortEvent
from ...core.types import ActiveHunter, Hunter, KubernetesCluster, InformationDisclosure, RemoteCodeExec, UnauthenticatedAccess, AccessRisk

""" Helper functions """

# Will attempt to do request "req1" with the optional parameters.
# If fails it will attempt to do "req2" with the optional parameters.
# If once of the request success this method will return True, if both fail- False.
def helperFuncDo2Requests(req1, req2, is_verify=False, data=None, req_type="get"):
    try:
        r = helperDoRequest(req1, is_verify, data, req_type)
        has_remote_access_gained = (r.status_code == 200 and r.content != "")
        if has_remote_access_gained:
            return r
    except Exception:
        try:
            r = helperDoRequest(req2, is_verify, data, req_type)
            has_remote_access_gained = (r.status_code == 200 and r.content != "")
            if has_remote_access_gained:
                return r
        except Exception:
            return False  # None of the requests succeded..
    return False


def helperDoRequest(req, is_verify, data=None, req_type="get"):
    if req_type == "put":
        r = requests.put(req, verify=is_verify, timeout=3, data=data)
        return r
    elif req_type == "get":
        r = requests.get(req, verify=is_verify, timeout=3, data=data)
        return r


""" Vulnerabilities """
class EtcdRemoteWriteAccessEvent(Vulnerability, Event):
    """Remote write access might grant an attacker full control over the kubernetes cluster"""

    def __init__(self, write_res):
        Vulnerability.__init__(self, KubernetesCluster, name="Etcd Remote Write Access Event", category=RemoteCodeExec)
        self.evidence = write_res

class EtcdRemoteReadAccessEvent(Vulnerability, Event):
    """Remote read access might expose to an attacker cluster's possible exploits, secrets and more."""

    def __init__(self, keys):
        Vulnerability.__init__(self, KubernetesCluster,  name="Etcd Remote Read Access Event", category=AccessRisk)
        self.evidence = keys

class EtcdRemoteVersionDisclosureEvent(Vulnerability, Event):
    """Remote version disclosure might give an attacker a valuable data to attack a cluster"""

    def __init__(self, version):
        Vulnerability.__init__(self, KubernetesCluster, name="Etcd Remote version disclosure", category=InformationDisclosure)
        self.evidence = version

class EtcdAccessEnabledWithoutAuthEvent(Vulnerability, Event):
    """Etcd is accessible using HTTP (without authorization and authentication), it would allow a potential attacker to gain access to the etcd"""

    def __init__(self, version):
        Vulnerability.__init__(self, KubernetesCluster,  name="Etcd is accessible without authorization", category=UnauthenticatedAccess)
        self.evidence = version

# Active Hunter
@handler.subscribe(OpenPortEvent, predicate=lambda p: p.port == 2379)
class EtcdRemoteAccessActive(ActiveHunter):
    """Checks for remote write access to etcd"""

    def __init__(self, event):
        self.event = event
        self.write_evidence = ''

    def db_keys_write_access(self):
        logging.debug("Active hunter is attempting to write keys remotely on host " + self.event.host)
        data = {
            'value': 'remotely written data'
        }
        r_secure = "https://{host}:{port}/v2/keys/message".format(host=self.event.host, port=2379)
        r_not_secure = "http://{host}:{port}/v2/keys/message".format(host=self.event.host, port=2379)
        res = helperFuncDo2Requests(r_secure, r_not_secure)
        if res:
            self.write_evidence = res.content
            return True
        return False

    def execute(self):
        if self.db_keys_write_access():
            self.publish_event(EtcdRemoteWriteAccessEvent(self.write_evidence))

# Passive Hunter
@handler.subscribe(OpenPortEvent, predicate=lambda p: p.port == 2379)
class EtcdRemoteAccess(Hunter):
    """Etcd Remote Access
    Checks for remote availability of etcd, version, read access, write access
    """
    # TODO:
    # Check the etcd hunter on a remote cluster! (currently everything was checked only at 127.0.0.1:2379)
    def __init__(self, event):
        self.event = event
        self.version_evidence = ''
        self.keys_evidence = ''

    def db_keys_disclosure(self):
        logging.debug(self.event.host)
        logging.debug("Passive hunter is attempting to read etcd keys remotely")
        r_secure = "https://{host}:{port}/v2/keys".format(host=self.event.host, port=2379)
        r_not_secure = "http://{host}:{port}/v2/keys".format(host=self.event.host, port=2379)
        res = helperFuncDo2Requests(r_secure, r_not_secure)
        if res:
            self.keys_evidence = res.content
            return True
        return False

    def version_disclosure(self):
        logging.debug(self.event.host)
        logging.debug("Passive hunter is attempting to check etcd version remotely")
        r_secure = "https://{host}:{port}/version".format(host=self.event.host, port=2379)
        r_not_secure = "http://{host}:{port}/version".format(host=self.event.host, port=2379)
        res = helperFuncDo2Requests(r_secure, r_not_secure)
        if res:
            self.version_evidence = res.content
            return True
        return False

    def unauthorized_access(self):
        logging.debug(self.event.host)
        logging.debug("Passive hunter is attempting to access etcd without authorization")
        r_not_secure = "http://{host}:{port}/version".format(host=self.event.host, port=2379)
        res = helperFuncDo2Requests(r_not_secure, r_not_secure)  # We don't have to do 2 requests this time
        if res:
            return True
        return False

    def execute(self):
        if self.version_disclosure():
            self.publish_event(EtcdRemoteVersionDisclosureEvent(self.version_evidence))
            if self.unauthorized_access():
                self.publish_event(EtcdAccessEnabledWithoutAuthEvent(self.version_evidence))
            if self.db_keys_disclosure():
                self.publish_event(EtcdRemoteReadAccessEvent(self.keys_evidence))
