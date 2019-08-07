import logging
import json
import requests

from ...core.events import handler
from ...core.events.types import Vulnerability, Event
from ...core.types import Hunter, ActiveHunter, KubernetesCluster, RemoteCodeExec, AccessRisk, InformationDisclosure, \
    PrivilegeEscalation, DenialOfService
from .apiserver import K8sVersionDisclosure
from distutils.version import LooseVersion, StrictVersion

""" Vulnerabilities """


class ServerApiVersionEndPointAccessPE(Vulnerability, Event):
    """Node is vulnerable to critical CVE-2018-1002105"""

    def __init__(self, evidence):
        Vulnerability.__init__(self, KubernetesCluster, name="Critical Privilege Escalation CVE", category=PrivilegeEscalation)
        self.evidence = evidence


class ServerApiVersionEndPointAccessDos(Vulnerability, Event):
    """Node not patched for CVE-2019-1002100. Depending on your RBAC settings, a crafted json-patch could cause a Denial of Service."""

    def __init__(self, evidence):
        Vulnerability.__init__(self, KubernetesCluster, name="Denial of Service to Kubernetes API Server", category=DenialOfService)
        self.evidence = evidence


class CveUtils:
    @staticmethod
    def is_older_than(fix_versions, check_version):
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

# Passive Hunter
@handler.subscribe(K8sVersionDisclosure)
class IsVulnerableToCVEAttack(Hunter):
    """CVE hunter
    Checks if Node is running a Kubernetes version vulnerable to critical CVEs
    """

    def __init__(self, event):
        self.event = event
        self.api_server_evidence = ''
        self.k8sVersion = ''

    def check_cve_2018_1002105(self, api_version):
        fix_versions = ["1.10.11", "1.11.5", "1.12.3"]
        return CveUtils.is_older_than(fix_versions, check_version=api_version)

    def check_cve_2019_1002100(self, api_version):
        """
        Kubernetes v1.0.x-1.10.x
        Kubernetes v1.11.0-1.11.7 (fixed in v1.11.8)
        Kubernetes v1.12.0-1.12.5 (fixed in v1.12.6)
        Kubernetes v1.13.0-1.13.3 (fixed in v1.13.4)
        """
        fix_versions = ["1.11.8", "1.12.6", "1.13.4"]
        return CveUtils.is_older_than(fix_versions, check_version=api_version)

    def execute(self):
        logging.debug('Cve Hunter got version from the API server: {}'.format(self.event.version))
        
        if self.check_cve_2018_1002105(self.event.version):
            self.publish_event(ServerApiVersionEndPointAccessPE(self.event.version))

        if self.check_cve_2019_1002100(self.event.version):
            self.publish_event(ServerApiVersionEndPointAccessDos(self.event.version))


