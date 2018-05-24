import json
import logging
import urllib3
from enum import Enum

import requests

from events import ReadOnlyKubeletEvent, SecureKubeletEvent, OpenPortEvent, handler

class KubeletPorts(Enum):
    SECURED = 10250
    READ_ONLY = 10255

@handler.subscribe(OpenPortEvent, predicate= lambda x: x.port == 10255 or x.port == 10250)
class KubeletDiscovery(object):
    def __init__(self, event):
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self.event = event

    @property
    def read_only_access(self):
        r = requests.get("http://{host}:{port}/pods".format(host=self.event.host, port=self.event.port))
        return r.status_code == 200
    
    @property
    def secure_access(self):
        r = requests.get("https://{host}:{port}/pods".format(host=self.event.host, port=self.event.port), verify=False)
        return r.status_code == 200
    
    def execute(self):
        logging.debug("secure port on {}".format(self.event.port))
        if self.event.port == KubeletPorts.SECURED.value and self.secure_access:
            handler.publish_event(SecureKubeletEvent())
        elif self.event.port == KubeletPorts.READ_ONLY.value and self.read_only_access:
            handler.publish_event(ReadOnlyKubeletEvent())