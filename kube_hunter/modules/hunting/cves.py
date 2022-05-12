import logging
from packaging import version

from kube_hunter.conf import get_config
from kube_hunter.core.events.event_handler import handler

from kube_hunter.core.events.types import K8sVersionDisclosure, Vulnerability, Event
from kube_hunter.core.types import (
    Hunter,
    KubectlClient,
    KubernetesCluster,
    CVERemoteCodeExecutionCategory,
    CVEPrivilegeEscalationCategory,
    CVEDenialOfServiceTechnique,
)
from kube_hunter.modules.discovery.kubectl import KubectlClientEvent

logger = logging.getLogger(__name__)
config = get_config()


class ServerApiVersionEndPointAccessPE(Vulnerability, Event):
    """Node is vulnerable to critical CVE-2018-1002105"""

    def __init__(self, evidence):
        Vulnerability.__init__(
            self,
            KubernetesCluster,
            name="Critical Privilege Escalation CVE",
            category=CVEPrivilegeEscalationCategory,
            vid="KHV022",
        )
        self.evidence = evidence


class ServerApiVersionEndPointAccessDos(Vulnerability, Event):
    """Node not patched for CVE-2019-1002100. Depending on your RBAC settings,
    a crafted json-patch could cause a Denial of Service."""

    def __init__(self, evidence):
        Vulnerability.__init__(
            self,
            KubernetesCluster,
            name="Denial of Service to Kubernetes API Server",
            category=CVEDenialOfServiceTechnique,
            vid="KHV023",
        )
        self.evidence = evidence


class PingFloodHttp2Implementation(Vulnerability, Event):
    """Node not patched for CVE-2019-9512. an attacker could cause a
    Denial of Service by sending specially crafted HTTP requests."""

    def __init__(self, evidence):
        Vulnerability.__init__(
            self,
            KubernetesCluster,
            name="Possible Ping Flood Attack",
            category=CVEDenialOfServiceTechnique,
            vid="KHV024",
        )
        self.evidence = evidence


class ResetFloodHttp2Implementation(Vulnerability, Event):
    """Node not patched for CVE-2019-9514. an attacker could cause a
    Denial of Service by sending specially crafted HTTP requests."""

    def __init__(self, evidence):
        Vulnerability.__init__(
            self,
            KubernetesCluster,
            name="Possible Reset Flood Attack",
            category=CVEDenialOfServiceTechnique,
            vid="KHV025",
        )
        self.evidence = evidence


class ServerApiClusterScopedResourcesAccess(Vulnerability, Event):
    """Api Server not patched for CVE-2019-11247.
    API server allows access to custom resources via wrong scope"""

    def __init__(self, evidence):
        Vulnerability.__init__(
            self,
            KubernetesCluster,
            name="Arbitrary Access To Cluster Scoped Resources",
            category=CVEPrivilegeEscalationCategory,
            vid="KHV026",
        )
        self.evidence = evidence


class IncompleteFixToKubectlCpVulnerability(Vulnerability, Event):
    """The kubectl client is vulnerable to CVE-2019-11246,
    an attacker could potentially execute arbitrary code on the client's machine"""

    def __init__(self, binary_version):
        Vulnerability.__init__(
            self,
            KubectlClient,
            "Kubectl Vulnerable To CVE-2019-11246",
            category=CVERemoteCodeExecutionCategory,
            vid="KHV027",
        )
        self.binary_version = binary_version
        self.evidence = f"kubectl version: {self.binary_version}"


class KubectlCpVulnerability(Vulnerability, Event):
    """The kubectl client is vulnerable to CVE-2019-1002101,
    an attacker could potentially execute arbitrary code on the client's machine"""

    def __init__(self, binary_version):
        Vulnerability.__init__(
            self,
            KubectlClient,
            "Kubectl Vulnerable To CVE-2019-1002101",
            category=CVERemoteCodeExecutionCategory,
            vid="KHV028",
        )
        self.binary_version = binary_version
        self.evidence = f"kubectl version: {self.binary_version}"


class CveUtils:
    @staticmethod
    def get_base_release(full_ver):
        # if LegacyVersion, converting manually to a base version
        if isinstance(full_ver, version.LegacyVersion):
            return version.parse(".".join(full_ver._version.split(".")[:2]))
        return version.parse(".".join(map(str, full_ver._version.release[:2])))

    @staticmethod
    def to_legacy(full_ver):
        # converting version to version.LegacyVersion
        return version.LegacyVersion(".".join(map(str, full_ver._version.release)))

    @staticmethod
    def to_raw_version(v):
        if not isinstance(v, version.LegacyVersion):
            return ".".join(map(str, v._version.release))
        return v._version

    @staticmethod
    def version_compare(v1, v2):
        """Function compares two versions, handling differences with conversion to LegacyVersion"""
        # getting raw version, while striping 'v' char at the start. if exists.
        # removing this char lets us safely compare the two version.
        v1_raw = CveUtils.to_raw_version(v1).strip("v")
        v2_raw = CveUtils.to_raw_version(v2).strip("v")
        new_v1 = version.LegacyVersion(v1_raw)
        new_v2 = version.LegacyVersion(v2_raw)

        return CveUtils.basic_compare(new_v1, new_v2)

    @staticmethod
    def basic_compare(v1, v2):
        return (v1 > v2) - (v1 < v2)

    @staticmethod
    def is_downstream_version(version):
        return any(c in version for c in "+-~")

    @staticmethod
    def is_vulnerable(fix_versions, check_version, ignore_downstream=False):
        """Function determines if a version is vulnerable,
        by comparing to given fix versions by base release"""
        if ignore_downstream and CveUtils.is_downstream_version(check_version):
            return False

        vulnerable = False
        check_v = version.parse(check_version)
        base_check_v = CveUtils.get_base_release(check_v)

        # default to classic compare, unless the check_version is legacy.
        version_compare_func = CveUtils.basic_compare
        if isinstance(check_v, version.LegacyVersion):
            version_compare_func = CveUtils.version_compare

        if check_version not in fix_versions:
            # comparing ease base release for a fix
            for fix_v in fix_versions:
                fix_v = version.parse(fix_v)
                base_fix_v = CveUtils.get_base_release(fix_v)

                # if the check version and the current fix has the same base release
                if base_check_v == base_fix_v:
                    # when check_version is legacy, we use a custom compare func, to handle differences between versions
                    if version_compare_func(check_v, fix_v) == -1:
                        # determine vulnerable if smaller and with same base version
                        vulnerable = True
                        break

        # if we did't find a fix in the fix releases, checking if the version is smaller that the first fix
        if not vulnerable and version_compare_func(check_v, version.parse(fix_versions[0])) == -1:
            vulnerable = True

        return vulnerable


@handler.subscribe_once(K8sVersionDisclosure, is_register=config.enable_cve_hunting)
class K8sClusterCveHunter(Hunter):
    """K8s CVE Hunter
    Checks if Node is running a Kubernetes version vulnerable to
    specific important CVEs
    """

    def __init__(self, event):
        self.event = event

    def execute(self):
        config = get_config()
        logger.debug(f"Checking known CVEs for k8s API version: {self.event.version}")
        cve_mapping = {
            ServerApiVersionEndPointAccessPE: ["1.10.11", "1.11.5", "1.12.3"],
            ServerApiVersionEndPointAccessDos: ["1.11.8", "1.12.6", "1.13.4"],
            ResetFloodHttp2Implementation: ["1.13.10", "1.14.6", "1.15.3"],
            PingFloodHttp2Implementation: ["1.13.10", "1.14.6", "1.15.3"],
            ServerApiClusterScopedResourcesAccess: ["1.13.9", "1.14.5", "1.15.2"],
        }
        for vulnerability, fix_versions in cve_mapping.items():
            if CveUtils.is_vulnerable(fix_versions, self.event.version, not config.include_patched_versions):
                self.publish_event(vulnerability(self.event.version))


# Removed due to incomplete implementation for multiple vendors revisions of kubernetes
@handler.subscribe(KubectlClientEvent)
class KubectlCVEHunter(Hunter):
    """Kubectl CVE Hunter
    Checks if the kubectl client is vulnerable to specific important CVEs
    """

    def __init__(self, event):
        self.event = event

    def execute(self):
        config = get_config()
        cve_mapping = {
            KubectlCpVulnerability: ["1.11.9", "1.12.7", "1.13.5", "1.14.0"],
            IncompleteFixToKubectlCpVulnerability: ["1.12.9", "1.13.6", "1.14.2"],
        }
        logger.debug(f"Checking known CVEs for kubectl version: {self.event.version}")
        for vulnerability, fix_versions in cve_mapping.items():
            if CveUtils.is_vulnerable(fix_versions, self.event.version, not config.include_patched_versions):
                self.publish_event(vulnerability(binary_version=self.event.version))
