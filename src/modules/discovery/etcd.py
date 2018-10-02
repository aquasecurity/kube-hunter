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
    """Remote write from anonymous user can give him full control over the kubernetes cluster"""
    def __init__(self):
        Service.__init__(self, name="Etcd Remote Write Access Event")
class etcdRemoteReadAccessEvent(Service, Event):
    """Remote read access from anonymous user might expose cluster exploits and secrets, more."""
    def __init__(self):
        Service.__init__(self, name="Etcd Remote Read Access Event")

"event handlers"
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
        r_secure = requests.get("https://{host}:{port}/v2/keys".format(host=self.event.host, port=2379), timeout=5)#decide which port to choose (maybe the host's port?)
        r_not_secure = requests.get("http://{host}:{port}/v2/keys".format(host=self.event.host, port=2379), timeout=5)#decide which port to choose (maybe the host's port?)
        has_remote_access_gained = (r_secure.status_code == 200 and r_secure.content != "") or (r_not_secure.status_code == 200 and r_not_secure.content != "")
        if has_remote_access_gained:
            self.publish_event(etcdRemoteReadAccessEvent(secure=False))
            return True
        return False

    def db_keys_write_access(self):
        logging.debug(self.event.host)
        logging.debug("Active hunter* is attempting to write keys remotely")
        data = {
            'value': 'remote write access penetration'
        }
        r_secure = requests.put("https://{host}:{port}/v2/keys/message".format(host=self.event.host, port=2379), data=data, timeout=5)#decide which port to choose (maybe the host's port?)
        r_not_secure = requests.put("https://{host}:{port}/v2/keys/message".format(host=self.event.host, port=2379), data=data, timeout=5)#decide which port to choose (maybe the host's port?)

        has_remote_access_gained = (r_secure.status_code == 200 and r_secure.content != "") or (r_not_secure.status_code == 200 and r_not_secure.content != "")
        if has_remote_access_gained:
            self.publish_event(etcdRemoteWriteAccessEvent(secure=False))
            return True
        return False

    def version_disclosure(self):
        logging.debug(self.event.host)
        logging.debug("Passive hunter is attempting to check etcd version remotely")
        r_secure = requests.get("https://{host}:{port}/version".format(host=self.event.host, port=2379), timeout=5)  # decide which port to choose (maybe the host's port?)
        r_not_secure = requests.get("http://{host}:{port}/version".format(host=self.event.host, port=2379), timeout=5)  # decide which port to choose (maybe the host's port?)

        has_remote_access_gained = (r_secure.status_code == 200 and r_secure.content != "") or (r_not_secure.status_code == 200 and r_not_secure.content != "")
        if has_remote_access_gained:
            self.publish_event(etcdRemoteReadAccessEvent(secure=False))
            return True
        return False

    def execute(self):
       if (self.version_disclosure()):
           self.db_keys_disclosure()
           self.db_keys_write_access()
