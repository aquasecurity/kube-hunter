import json
import logging
from enum import Enum
from ...core.types import Hunter, Kubelet

import requests
import urllib3

from ...core.events import handler
from ...core.events.types import OpenPortEvent, Vulnerability, Event, Service
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

""" Services """
class ReadOnlyKubeletEvent(Service, Event):
    """Can expose specific handlers which reveals information about the node/cluster"""
    def __init__(self):
        Service.__init__(self, name="Kubelet API (readonly)")

class SecureKubeletEvent(Service, Event):
    """The kubelet ensures that all containers on the node are running and healthy"""
    def __init__(self, cert=False, token=False):
        self.cert = cert
        self.token = token
        Service.__init__(self, name="Kubelet API") 


class KubeletPorts(Enum):
    SECURED = 10250
    READ_ONLY = 10255

@handler.subscribe(OpenPortEvent, predicate= lambda x: x.port == 10255 or x.port == 10250)
class KubeletDiscovery(Hunter):
    def __init__(self, event):
        self.event = event

    def get_read_only_access(self):
        logging.debug(self.event.host)
        r = requests.get("http://{host}:{port}/pods".format(host=self.event.host, port=self.event.port))
        if r.status_code == 200:
            self.publish_event(ReadOnlyKubeletEvent())
        
    def get_secure_access(self):
        event = SecureKubeletEvent()
        if self.ping_kubelet(authenticate=False) == 200:
            event.secure = False
        # anonymous authentication is disabled
        elif self.ping_kubelet(authenticate=True) == 200: 
            event.secure = True
        self.publish_event(event)

    def ping_kubelet(self, authenticate):
        r = requests.Session()
        if authenticate: 
            if self.event.auth_token:
                r.headers.update({
                    "Authorization": "Bearer {}".format(self.event.auth_token)
                })
            if self.event.client_cert:
                r.cert = self.event.client_cert
        r.verify = False
        try:
            return r.get("https://{host}:{port}/pods".format(host=self.event.host, port=self.event.port)).status_code
        except Exception as ex:
            logging.debug("Failed pinging secured kubelet {} : {}".format(self.event.host, ex.message))

    def execute(self):
        if self.event.port == KubeletPorts.SECURED.value:
            self.get_secure_access()
        elif self.event.port == KubeletPorts.READ_ONLY.value:
            self.get_read_only_access()