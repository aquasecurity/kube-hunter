import json
import logging
from enum import Enum
from ..types import Hunter

import requests
import urllib3

from ..events import handler
from ..events.types import OpenPortEvent, Kubelet, Vulnerability, Event, Service
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

""" Services """
class ReadOnlyKubeletEvent(Service, Event):
    """Exposes specific handlers which disclose sensitive information about the cluster"""
    def __init__(self):
        Service.__init__(self, name="Kubelet API (readonly)")

class SecureKubeletEvent(Service, Event):
    """Exposes handlers that can perform unwanted operations on pods/containers"""
    def __init__(self, cert=False, token=False):
        self.cert = cert
        self.token = token
        Service.__init__(self, name="Kubelet API") 


""" Vulnerabilities """
class PodsHandler:
    """Exposes sensitive information about pods that are bound to the node"""
    name="/pods"

class KubeletExposedHandler(Vulnerability, Event):
    def __init__(self, handler):
        self.handler = handler
        Vulnerability.__init__(self, Kubelet, "Handler Exposure")

    def get_name(self):
        return "{} - {}".format(self.name, self.handler.name)

    def explain(self):
        return self.handler.__doc__

class AnonymousAuthEnabled(Vulnerability, Event):
    """Anonymous Auth to the kubelet, exposes secure access to all requests on the kubelet"""
    def __init__(self):
        Vulnerability.__init__(self, Kubelet, "Anonymous Authentication")

    def proof(self):
        pass # TODO: decide on an appropriate proof



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
            self.publish_event(KubeletExposedHandler(handler=PodsHandler))
            self.publish_event(ReadOnlyKubeletEvent())
        
    def get_secure_access(self):
        event = SecureKubeletEvent()
        if self.ping_kubelet(authenticate=False) == 200:
            self.publish_event(KubeletExposedHandler(handler=PodsHandler))
            self.publish_event(AnonymousAuthEnabled())
            event.anonymous_auth = True
        # anonymous authentication is disabled
        elif self.ping_kubelet(authenticate=True) == 200: 
            event.anonymous_auth = False
        self.publish_event(event)

    def ping_kubelet(self, authenticate=False):
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