import logging
import packaging.version

from typing import ClassVar, Dict, List, Type
from kube_hunter.conf import get_config
from kube_hunter.core.events import K8sVersionDisclosure
from kube_hunter.core.pubsub.subscription import subscribe, subscribe_once
from kube_hunter.core.types import (
    DenialOfService,
    Hunter,
    KubectlClient,
    KubernetesCluster,
    PrivilegeEscalation,
    RemoteCodeExec,
    Vulnerability,
)
from kube_hunter.modules.discovery.kubectl import KubectlClientFound

logger = logging.getLogger(__name__)
CVEMapping = Dict[Type[Vulnerability], List[str]]


class ServerApiVersionEndPointAccessPE(Vulnerability):
    """Node is vulnerable to critical CVE-2018-1002105"""

    def __init__(self, evidence: str):
        super().__init__(
            name="Critical Privilege Escalation CVE",
            component=KubernetesCluster,
            category=PrivilegeEscalation,
            vid="KHV022",
            evidence=evidence,
        )


class ServerApiVersionEndPointAccessDos(Vulnerability):
    """Node not patched for CVE-2019-1002100. Depending on your RBAC settings,
    a crafted json-patch could cause a Denial of Service"""

    def __init__(self, evidence):
        super().__init__(
            name="Denial of Service to Kubernetes API Server",
            component=KubernetesCluster,
            category=DenialOfService,
            vid="KHV023",
            evidence=evidence,
        )


class PingFloodHTTP2(Vulnerability):
    """Node not patched for CVE-2019-9512. an attacker could cause a
    Denial of Service by sending specially crafted HTTP requests"""

    def __init__(self, evidence):
        super().__init__(
            name="Possible Ping Flood Attack",
            component=KubernetesCluster,
            category=DenialOfService,
            vid="KHV024",
            evidence=evidence,
        )


class ResetFloodHTTP2(Vulnerability):
    """Node not patched for CVE-2019-9514. an attacker could cause a
    Denial of Service by sending specially crafted HTTP requests"""

    def __init__(self, evidence):
        super().__init__(
            name="Possible Reset Flood Attack",
            component=KubernetesCluster,
            category=DenialOfService,
            vid="KHV025",
            evidence=evidence,
        )


class ServerApiClusterScopedResourcesAccess(Vulnerability):
    """Api Server not patched for CVE-2019-11247.
    API server allows access to custom resources via wrong scope"""

    def __init__(self, evidence):
        super().__init__(
            name="Arbitrary Access To Cluster Scoped Resources",
            component=KubernetesCluster,
            category=PrivilegeEscalation,
            vid="KHV026",
            evidence=evidence,
        )


class IncompleteFixToKubectlCpVulnerability(Vulnerability):
    """The kubectl client is vulnerable to CVE-2019-11246,
    an attacker could potentially execute arbitrary code on the client's machine"""

    binary_version: str

    def __init__(self, binary_version: str):
        super().__init__(
            name="Kubectl Vulnerable To CVE-2019-11246",
            component=KubectlClient,
            category=RemoteCodeExec,
            vid="KHV027",
            evidence=f"kubectl version: {binary_version}",
        )
        self.binary_version = binary_version


class KubectlCpVulnerability(Vulnerability):
    """The kubectl client is vulnerable to CVE-2019-1002101,
    an attacker could potentially execute arbitrary code on the client's machine"""

    def __init__(self, binary_version):
        super().__init__(
            name="Kubectl Vulnerable To CVE-2019-1002101",
            component=KubectlClient,
            category=RemoteCodeExec,
            vid="KHV028",
            evidence=f"kubectl version: {binary_version}",
        )
        self.binary_version = binary_version


class CVEUtils:
    @staticmethod
    def get_base_release(full_ver):
        # if LegacyVersion, converting manually to a base version
        if isinstance(full_ver, packaging.version.LegacyVersion):
            return packaging.version.parse(".".join(full_ver._version.split(".")[:2]))
        return packaging.version.parse(".".join(map(str, full_ver._version.release[:2])))

    @staticmethod
    def to_raw_version(v):
        if not isinstance(v, packaging.version.LegacyVersion):
            return ".".join(map(str, v._version.release))
        return v._version

    @staticmethod
    def version_compare(v1, v2):
        """Function compares two versions, handling differences with conversion to LegacyVersion"""
        # getting raw version, while striping 'v' char at the start. if exists.
        # removing this char lets us safely compare the two version.
        v1_raw = CVEUtils.to_raw_version(v1).strip("v")
        v2_raw = CVEUtils.to_raw_version(v2).strip("v")
        new_v1 = packaging.version.LegacyVersion(v1_raw)
        new_v2 = packaging.version.LegacyVersion(v2_raw)

        return CVEUtils.basic_compare(new_v1, new_v2)

    @staticmethod
    def basic_compare(v1, v2):
        return (v1 > v2) - (v1 < v2)

    @staticmethod
    def is_downstream_version(version):
        return any(c in version for c in "+-~")

    @staticmethod
    def is_vulnerable(fix_versions: List[str], check_version: str, ignore_downstream=False):
        """Function determines if a version is vulnerable,
        by comparing to given fix versions by base release"""
        if ignore_downstream and CVEUtils.is_downstream_version(check_version):
            return False

        vulnerable = False
        check_v = packaging.version.parse(check_version)
        base_check_v = CVEUtils.get_base_release(check_v)

        # default to classic compare, unless the check_version is legacy.
        version_compare_func = CVEUtils.basic_compare
        if isinstance(check_v, packaging.version.LegacyVersion):
            version_compare_func = CVEUtils.version_compare

        if check_version not in fix_versions:
            # comparing ease base release for a fix
            for raw_fix_v in fix_versions:
                fix_v = packaging.version.parse(raw_fix_v)
                base_fix_v = CVEUtils.get_base_release(fix_v)

                # if the check version and the current fix has the same base release
                if base_check_v == base_fix_v:
                    # when check_version is legacy, we use a custom compare func, to handle differences between versions
                    if version_compare_func(check_v, fix_v) == -1:
                        # determine vulnerable if smaller and with same base version
                        vulnerable = True
                        break

        # if we did't find a fix in the fix releases, checking if the version is smaller that the first fix
        if not vulnerable and version_compare_func(check_v, packaging.version.parse(fix_versions[0])) == -1:
            vulnerable = True

        return vulnerable

    @staticmethod
    def check_many(check_version: str, mapping: CVEMapping, ignore_downstream=False):
        for item, fix_versions in mapping.items():
            if CVEUtils.is_vulnerable(fix_versions, check_version, ignore_downstream):
                yield item


@subscribe_once(K8sVersionDisclosure)
class KubernetesClusterCVEHunter(Hunter):
    """K8s CVE Hunter
    Checks if Node is running a Kubernetes version vulnerable to
    specific important CVEs
    """

    cve_mapping: ClassVar[CVEMapping] = {
        ServerApiVersionEndPointAccessPE: ["1.10.11", "1.11.5", "1.12.3"],
        ServerApiVersionEndPointAccessDos: ["1.11.8", "1.12.6", "1.13.4"],
        ServerApiClusterScopedResourcesAccess: ["1.13.9", "1.14.5", "1.15.2"],
        ResetFloodHTTP2: ["1.13.10", "1.14.6", "1.15.3"],
        PingFloodHTTP2: ["1.13.10", "1.14.6", "1.15.3"],
    }
    event: K8sVersionDisclosure

    def execute(self):
        ignore_downstream = not get_config().include_patched_versions
        logger.debug(f"Checking known CVEs for k8s API version: {self.event.version}")

        for vulnerability in CVEUtils.check_many(self.event.version, self.cve_mapping, ignore_downstream):
            yield vulnerability(self.event.version)


@subscribe(KubectlClientFound)
class KubectlCVEHunter(Hunter):
    """Kubectl CVE Hunter
    Checks if the kubectl client is vulnerable to specific important CVEs
    """

    cve_mapping: ClassVar[CVEMapping] = {
        KubectlCpVulnerability: ["1.11.9", "1.12.7", "1.13.5", "1.14.0"],
        IncompleteFixToKubectlCpVulnerability: ["1.12.9", "1.13.6", "1.14.2"],
    }
    event: KubectlClientFound

    def execute(self):
        ignore_downstream = not get_config().include_patched_versions
        logger.debug(f"Checking known CVEs for kubectl version: {self.event.version}")

        for vulnerability in CVEUtils.check_many(self.event.version, self.cve_mapping, not ignore_downstream):
            yield vulnerability(self.event.version)
