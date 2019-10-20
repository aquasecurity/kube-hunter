
import logging
import subprocess 
import json

from ...core.types import Discovery
from ...core.events import handler
from ...core.events.types import HuntStarted, Event


class KubeStateMetricsEvent(Event):
    """Add-on agent to generate and expose cluster-level metrics."""
    def __init__(self, version):
        self.version = version

# Will be triggered on start of every hunt 
@handler.subscribe(HuntStarted)
class KubeStateMetricsDiscovery(Discovery):
    """kube-state-metrics version Discovery
    Checks the version of kube-state-metrics part of CVE-2019-17110 vulnerability check
    """
    def __init__(self, event):
        self.event = event

    def get_kube_state_metrics_version(self):
        version = None
        try:
            # kube-state-metrics affected versions: v1.7.0 and v1.7.1
            kubectl_cmd = "kubectl get deployment -n kube-system kube-state-metrics -o yaml | grep image:"
            version_info = subprocess.check_output(kubectl_cmd, stderr=subprocess.STDOUT)
            version_info = version_info.decode()
            # expected output format: "v1.7.0"
            version = version_info.split(":")[-1].strip()
        except Exception as x:
            logging.debug("Could not find kubectl client")
        return version
    
    def execute(self):
        logging.debug("Attempting to discover kube-state-metrics version")
        version = self.get_kube_state_metrics_version() 
        if version:
            self.publish_event(KubeStateMetricsEvent(version=version))