import json
import logging

import requests

from ...core.events import handler
from ...core.events.types import Event, OpenPortEvent, Service
from ...core.types import Hunter

"""Etcd is a DB that stores cluster's data,
    it contains configuration and current state information, and might contain secrets"""
#services:

class etcdRemoteWriteAccessEvent(Service, Event):
    """Remote write access might grant an attacker full control over the kubernetes cluster"""
    def __init__(self):
        Service.__init__(self, name="Etcd Remote Write Access Event")
class etcdRemoteReadAccessEvent(Service, Event):
    """Remote read access might expose to an attacker cluster's possible exploits, secrets and more."""
    def __init__(self):
        Service.__init__(self, name="Etcd Remote Read Access Event")
class etcdRemoteVersionDisclosureEvent(Service, Event):
    """Remote version disclosure might give an attacker a valuable data to attack a cluster"""
    def __init__(self):
        Service.__init__(self, name="Etcd Remote version disclosure")
class etcdAccessEnabledWithoutAuthEvent(Service, Event):
    """Remote version disclosure might give an attacker a valuable data to attack a cluster"""
    def __init__(self):
        Service.__init__(self, name="Etcd is accessible without authorization")



@handler.subscribe(OpenPortEvent, predicate= lambda p: p.port == 2379)
class etcdRemoteAccess(Hunter):
    """Etcd Remote Access
    Checks for remote availability of etcd, version, read access, write access
    """
    #TODO:
    #Read Liz's book & etcd's rest api and check if I've missed important commands to check
    #Do we need to add a auth check and remote connection?->>>
    #->>>if we are able to get the version remotely it means there was no auth check and we were able to connect remotely but maybe we should display the no auth event anyway?
    #Check why the execute() isn't being called
    #Decide if I should move db_keys_write_access to hunting/etcd.py as an active hunter
    def __init__(self, event):
        self.event = event

    def db_keys_disclosure(self):
        logging.debug(self.event.host)
        logging.debug("Passive hunter is attempting to read etcd keys remotely")
        r_secure = "https://{host}:{port}/v2/keys".format(host=self.event.host, port=2379)
        r_not_secure = "http://{host}:{port}/v2/keys".format(host=self.event.host, port=2379)

        if self.helperFuncDo2Requests(r_secure, r_not_secure):
            self.publish_event(etcdRemoteReadAccessEvent())
            return True
        return False

    def db_keys_write_access(self):
        logging.debug(self.event.host)
        logging.debug("Active hunter* is attempting to write keys remotely")
        data = {
            'value': 'remote write access penetration'
        }
        r_secure = "https://{host}:{port}/v2/keys/message".format(host=self.event.host, port=2379)
        r_not_secure = "https://{host}:{port}/v2/keys/message".format(host=self.event.host, port=2379)

        if self.helperFuncDo2Requests(r_secure, r_not_secure, data=data, reqType="put"):
            self.publish_event(etcdRemoteWriteAccessEvent())
            return True
        return False

    def version_disclosure(self):
        logging.debug(self.event.host)
        logging.debug("Passive hunter is attempting to check etcd version remotely")
        r_secure = "https://{host}:{port}/version".format(host=self.event.host, port=2379)
        r_not_secure = "http://{host}:{port}/version".format(host=self.event.host, port=2379)
        if self.helperFuncDo2Requests( r_secure, r_not_secure ):
            self.publish_event(etcdRemoteVersionDisclosureEvent())
            return True
        return False

    def execute(self):
        if (self.version_disclosure()):
           self.publish_event(etcdAccessEnabledWithoutAuthEvent())#if version is accessible we can publish "no auth event".
           self.db_keys_disclosure()
           self.db_keys_write_access()

    def helperFuncDo2Requests(self, req1, req2, isVerify=False, data=None, reqType="get"):
        try:
            r = self.helperDoRequest(req1, isVerify, data, reqType)
            has_remote_access_gained = (r.status_code == 200 and r.content != "")
            if has_remote_access_gained:
                return True
        except Exception:
            try:
                r = self.helperDoRequest(req2, isVerify, data, reqType)
                has_remote_access_gained = (r.status_code == 200 and r.content != "")
                if has_remote_access_gained:
                    return True
            except Exception:
                return False #None of the requests succeded..
        return False

    def helperDoRequest(self, req, isVerify, data=None, reqType="get"):
        if reqType == "put":
            r = requests.put(req, verify=isVerify, timeout=3, data=data)
            return r
        elif reqType == "get":
            r = requests.get(req, verify=isVerify, timeout=3, data=data)
            return r