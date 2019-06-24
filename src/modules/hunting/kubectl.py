import logging

from ...core.events import handler
from ...core.types import Hunter, RemoteCodeExec, KubectlClient
from ...core.events.types import Vulnerability, Event
from ..discovery.kubectl import KubectlClientEvent

from distutils.version import LooseVersion, StrictVersion

class KubectlCopyVulnerability(Vulnerability, Event):
    """The kubectl client is vulnerable to CVE-2019-11246, an attacker could potentially execute arbitrary code on the client's machine"""
    def __init__(self, binary_version):
        Vulnerability.__init__(self, KubectlClient, "Kubectl Copy Vulnerability", category=RemoteCodeExec)
        self.binary_version = binary_version
        self.evidence = "kubectl version: {}".format(self.binary_version)


@handler.subscribe(KubectlClientEvent)
class KubectlCopyHunter(Hunter):
    """Kubectl Copy Vulnerability Hunter
    Compares version of the kubectl binary to known CVE-2019-11246 vulnerable versions 
    """
    def __init__(self, event):
        self.event = event
        self.fixed_versions = ['1.12.9', '1.13.6', '1.14.2'] # ordered

    def is_vulnerable(self, binary_v):
        logging.debug("Passive hunter is comparing the kubectl binary version to vulnerable versions")
        # in case version is in short version, converting
        if len(LooseVersion(binary_v).version) < 3:
            binary_v += '.0'

        vulnerable = False
        if binary_v not in self.fixed_versions:            
            for fix_v in self.fixed_versions:
                fix_v = LooseVersion(fix_v)
                base_v = '.'.join(map(lambda x: str(x), fix_v.version[:2]) )

                if binary_v.startswith(base_v): 
                    if LooseVersion(binary_v) < fix_v:
                        vulnerable = True
                        break
        
        # if version is smaller than smaller fix version
        if not vulnerable and LooseVersion(binary_v) < LooseVersion(self.fixed_versions[0]):
            vulnerable = True
        logging.debug("Could not match kubectl with known fix versions, determining vulnerable to kubectl cp vuln")
        return vulnerable

    def execute(self):
        if self.is_vulnerable(self.event.version):
            self.publish_event(KubectlCopyVulnerability(binary_version=self.event.version))