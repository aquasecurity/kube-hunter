import logging

from ...core.events import handler
from ...core.types import Hunter, RemoteCodeExec, KubectlClient
from ...core.events.types import Vulnerability, Event
from ..discovery.kubectl import KubectlClientEvent

from distutils.version import LooseVersion, StrictVersion

class IncompleteFixToKubectlCpVulnerability(Vulnerability, Event):
    """The kubectl client is vulnerable to CVE-2019-11246, an attacker could potentially execute arbitrary code on the client's machine"""
    def __init__(self, binary_version):
        Vulnerability.__init__(self, KubectlClient, "Kubectl Vulnerable To CVE-2019-11246", category=RemoteCodeExec)
        self.binary_version = binary_version
        self.evidence = "kubectl version: {}".format(self.binary_version)

class KubectlCpVulnerability(Vulnerability, Event):
    """The kubectl client is vulnerable to CVE-2019-1002101, an attacker could potentially execute arbitrary code on the client's machine"""
    def __init__(self, binary_version):
        Vulnerability.__init__(self, KubectlClient, "Kubectl Vulnerable To CVE-2019-1002101", category=RemoteCodeExec)
        self.binary_version = binary_version
        self.evidence = "kubectl version: {}".format(self.binary_version)


@handler.subscribe(KubectlClientEvent)
class KubectlCVEHunter(Hunter):
    """Kubectl CVE Hunter
    Compares version of the kubectl binary to known CVE affected versions
    """
    def __init__(self, event):
        self.event = event

    def is_older_than(self, fix_versions, check_version):
        """Function determines if a version is vulnerable, by comparing to given fix versions"""
        logging.debug("Passive hunter is comparing the kubectl binary version to vulnerable versions")
        # in case version is in short version, converting
        if len(LooseVersion(check_version).version) < 3:
            check_version += '.0'

        vulnerable = False
        if check_version not in fix_versions:
            for fix_v in fix_versions:
                fix_v = LooseVersion(fix_v)
                base_v = '.'.join(map(lambda x: str(x), fix_v.version[:2]) )

                if check_version.startswith(base_v):
                    if LooseVersion(check_version) < fix_v:
                        vulnerable = True
                        break
        # if version is smaller than smaller fix version
        if not vulnerable and LooseVersion(check_version) < LooseVersion(fix_versions[0]):
            vulnerable = True

        return vulnerable

    def execute(self):
        cve_2019_1002101_fix_versions = ['1.11.9', '1.12.7', '1.13.5' '1.14.0']
        cve_2019_11246_fix_versions = ['1.12.9', '1.13.6', '1.14.2']

        if self.is_older_than(fix_versions=cve_2019_1002101_fix_versions, check_version=self.event.version):
            self.publish_event(KubectlCpVulnerability(binary_version=self.event.version))

        if self.is_older_than(fix_versions=cve_2019_11246_fix_versions, check_version=self.event.version):
            self.publish_event(IncompleteFixToKubectlCpVulnerability(binary_version=self.event.version))
