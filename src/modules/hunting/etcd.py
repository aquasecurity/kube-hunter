import json
import logging

import requests

from ...core.events import handler
from ...core.events.types import Vulnerability, Event, OpenPortEvent
from ...core.types import ActiveHunter

"""Etcd is a DB that stores cluster's data,
    it contains configuration and current state information, and might contain secrets"""
# Vulnerability:
class etcdRemoteWriteAccessEvent(Vulnerability, Event):
    """Remote write access might grant an attacker full control over the kubernetes cluster"""
    def __init__(self):
        Vulnerability.__init__(self, name="Etcd Remote Write Access Event")

@handler.subscribe(OpenPortEvent, predicate= lambda p: p.port == 2379)
class etcdRemoteAccessActive(ActiveHunter):
    """Etcd Remote Access
    Checks for remote write access to etcd
    """

    def __init__(self, event):
        self.event = event

    def db_keys_write_access(self):
        logging.debug(self.event.host)
        logging.debug("Active hunter is attempting to write keys remotely")
        data = {
            'value': 'remote write access penetration'
        }
        r_secure = "https://{host}:{port}/v2/keys/message".format(host=self.event.host, port=2379)
        r_not_secure = "https://{host}:{port}/v2/keys/message".format(host=self.event.host, port=2379)

        if self.helperFuncDo2Requests(r_secure, r_not_secure, data=data, req_type="put"):
            self.publish_event(etcdRemoteWriteAccessEvent())
            return True
        return False

    def execute(self):
       self.db_keys_write_access()

    # Will attempt to do request "req1" with the optional parameters.
    # If fails it will attempt to do "req2" with the optional parameters.
    # If once of the request success this method will return True, if both fail- False.
    def helperFuncDo2Requests(self, req1, req2, is_verify=False, data=None, req_type="get"):
        try:
            r = self.helperDoRequest(req1, is_verify, data, req_type)
            has_remote_access_gained = (r.status_code == 200 and r.content != "")
            if has_remote_access_gained:
                return True
        except Exception:
            try:
                r = self.helperDoRequest(req2, is_verify, data, req_type)
                has_remote_access_gained = (r.status_code == 200 and r.content != "")
                if has_remote_access_gained:
                    return True
            except Exception:
                return False #None of the requests succeded..
        return False

    def helperDoRequest(self, req, is_verify, data=None, req_type="get"):
        if req_type == "put":
            r = requests.put(req, verify=is_verify, timeout=3, data=data)
            return r
        elif req_type == "get":
            r = requests.get(req, verify=is_verify, timeout=3, data=data)
            return r