import json
import logging
from enum import Enum
from ..types import Hunter

import requests
import urllib3

from ..events import handler
from ..events.types import (OpenPortEvent, ReadOnlyKubeletEvent,
                          SecureKubeletEvent)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class KubeletPorts(Enum):
    SECURED = 10250
    READ_ONLY = 10255

@handler.subscribe(OpenPortEvent, predicate= lambda x: x.port == 10255 or x.port == 10250)
class KubeletDiscovery(Hunter):
    def __init__(self, event):
        self.event = event

    @property
    def read_only_access(self):
        logging.debug(self.event.host)
        r = requests.get("http://{host}:{port}/pods".format(host=self.event.host, port=self.event.port))
        return r.status_code == 200
    
    @property
    def secure_access(self):
        r = requests.get("https://{host}:{port}/pods".format(host=self.event.host, port=self.event.port), verify=False)
        return r.status_code == 200
    
    def execute(self):
        logging.debug("secure port on {}".format(self.event.port))
        if self.event.port == KubeletPorts.SECURED.value and self.secure_access:
            self.publish_event(SecureKubeletEvent())
        elif self.event.port == KubeletPorts.READ_ONLY.value and self.read_only_access:
            self.publish_event(ReadOnlyKubeletEvent())