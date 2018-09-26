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
@handler.subscribe(OpenPortEvent, predicate= lambda p: p.port == 2379 or p.port == 2370 or p.port == 2380)
class etcdRemoteAccess(Hunter):
    """etcd Remote Access
    Checks for availability of etcd, version, read access, write access
    """
    #TODO:
    #db_keys_write_access: Convert that curl command to a uri: curl http://127.0.0.1:2379/v2/keys/message -XPUT -d value="Hello world"
    #If we've got a read access-> check if data is encryption.
    #Read Liz's book & etcd's rest api and check if I've missed important commands to check
    #Do we need to add a auth check and remote connection?->>>
    #->>>if we are able to get the version remotely it means there was no auth check and we were able to connect remotely but maybe we should display it?
    #Add proper logs
    def __init__(self, event):
        self.event = event

    def db_keys_disclosure(self):
        logging.debug(self.event.host)
        r = requests.get("https://{host}:{port}/v2/keys".format(host=self.event.host, port=2379))#decide which port to choose (maybe the host's port?)
        if r.status_code == 200:
            self.publish_event(etcdRemoteReadAccessEvent(secure=False))
            return True
        return False

    def db_keys_write_access(self):
        logging.debug(self.event.host)
        r = requests.get("https://{host}:{port}/v2/keys".format(host=self.event.host, port=2379))#decide which port to choose (maybe the host's port?)
        if r.status_code == 200:
            self.publish_event(etcdRemoteWriteAccessEvent(secure=False))
            return True
        return False

    def version_disclosure(self):
        logging.debug(self.event.host)
        r = requests.get("https://{host}:{port}/version".format(host=self.event.host, port=2379))  # decide which port to choose (maybe the host's port?)
        if r.status_code == 200:
            self.publish_event(etcdRemoteReadAccessEvent(secure=False))
            return True
        return False


    def execute(self):
       if (self.version_disclosure()):
           self.db_keys_disclosure()
           self.db_keys_write_access()
