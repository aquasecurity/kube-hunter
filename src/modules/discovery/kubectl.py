
import logging
import subprocess 
import json

from ...core.types import Discovery
from ...core.events import handler
from ...core.events.types import HuntStarted, Event


class KubectlClientEvent(Event):
    """The API server is in charge of all operations on the cluster."""
    def __init__(self, version):
        self.version = version

# Will be triggered on start of every hunt 
@handler.subscribe(HuntStarted)
class KubectlClientDiscovery(Discovery):
    """Kubectl Client Discovery
    Checks for the existence of a local kubectl client
    """
    def __init__(self, event):
        self.event = event

    def get_kubectl_binary_version(self):
        version = None
        try:
            versionInfo = subprocess.check_output("kubectl version --client", stderr=subprocess.STDOUT)
            if b"GitVersion" in versionInfo:
                # extracting version from kubectl output
                versionInfo = versionInfo.decode()
                start = versionInfo.find('GitVersion')
                version = versionInfo[start + len("GitVersion':\"") : versionInfo.find("\",", start)]
        except Exception as x:
            logging.debug("Could not find kubectl client")
        return version
    
    def execute(self):
        logging.debug("Attempting to discover a local kubectl client")
        version = self.get_kubectl_binary_version() 
        if version:
            self.publish_event(KubectlClientEvent(version=version))