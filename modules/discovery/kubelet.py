import json
import logging
from enum import Enum
from ..types import Hunter

import requests
import urllib3

from ..events import handler
from ..events.types import (OpenPortEvent, ReadOnlyKubeletEvent,
                          SecureKubeletEvent, Vulnerability, Event)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@handler.subscribe(OpenPortEvent, predicate= lambda x: x.port == 10255 or x.port == 10250)
class KubeletDiscovery(Hunter):
    def __init__(self, event):
        self.event = event

    def get_read_only_access(self):
        logging.debug(self.event.host)
        r = requests.get("http://{host}:{port}/pods".format(host=self.event.host, port=self.event.port))
        if r.status_code == 200:
            self.publish_event(KubeletOpenHandler(handler="pods"))
            self.publish_event(ReadOnlyKubeletEvent())
        
    def get_secure_access(self):
        event = SecureKubeletEvent()
        if self.ping_kubelet(authenticate=False) == 200:
            self.publish_event(KubeletOpenHandler(handler="pods"))
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
        return r.get("https://{host}:{port}/pods".format(host=self.event.host, port=self.event.port)).status_code
   
    def execute(self):
        if self.event.port == KubeletPorts.SECURED.value:
            self.get_secure_access()
        elif self.event.port == KubeletPorts.READ_ONLY.value:
            self.get_read_only_access()


""" Types """
class KubeletOpenHandler(Vulnerability, Event):
    def __init__(self, handler, **kargs):
        self.handler = handler
        Vulnerability.__init__(self, name="Kubelet Exposure", **kargs)

    def explain(self):
        return "Handler - {}/ Kubelet Api - {}:{}".format(self.handler, self.host, self.port)


class AnonymousAuthEnabled(Vulnerability, Event):
    def __init__(self, **kargs):
        Vulnerability.__init__(self, name="Anonymous Authentication", **kargs)

    def explain(self):
        return "Kubelet - {}:{}".format(self.host, self.port)

class KubeletPorts(Enum):
    SECURED = 10250
    READ_ONLY = 10255
