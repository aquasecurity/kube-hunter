from kube_hunter.modules.hunting.all import active_hunters, all_hunters, passive_hunters, type_filter
from kube_hunter.modules.discovery.apiserver import ApiServiceDiscovery
from kube_hunter.modules.discovery.dashboard import KubeDashboard as KubeDashboardDiscovery
from kube_hunter.modules.discovery.etcd import EtcdRemoteAccess as EtcdRemoteAccessDiscovery
from kube_hunter.modules.discovery.hosts import FromPodHostDiscovery, HostDiscovery
from kube_hunter.modules.discovery.kubectl import KubectlClientDiscovery
from kube_hunter.modules.discovery.kubelet import KubeletDiscovery
from kube_hunter.modules.discovery.ports import PortDiscovery
from kube_hunter.modules.discovery.proxy import KubeProxy as KubeProxyDiscovery
from kube_hunter.modules.hunting.aks import AzureSpnHunter, ProveAzureSpnExposure
from kube_hunter.modules.hunting.apiserver import (
    AccessApiServer,
    ApiVersionHunter,
    AccessApiServerActive,
    AccessApiServerWithToken,
)
from kube_hunter.modules.hunting.arp import ARPSpoofHunter
from kube_hunter.modules.hunting.capabilities import PodCapabilitiesHunter
from kube_hunter.modules.hunting.certificates import CertificateDiscovery
from kube_hunter.modules.hunting.cves import KubernetesClusterCVEHunter, KubectlCVEHunter
from kube_hunter.modules.hunting.dashboard import KubeDashboard
from kube_hunter.modules.hunting.dns import DNSSpoofHunter
from kube_hunter.modules.hunting.etcd import EtcdRemoteAccess, EtcdRemoteAccessActive
from kube_hunter.modules.hunting.kubelet import (
    ReadOnlyKubeletPortHunter,
    SecureKubeletPortHunter,
    ProveRunHandler,
    ProveContainerLogsHandler,
    ProveSystemLogs,
)
from kube_hunter.modules.hunting.mounts import VarLogMountHunter, ProveVarLogMount
from kube_hunter.modules.hunting.proxy import KubeProxy, ProveProxyExposed, K8sVersionDisclosureProve
from kube_hunter.modules.hunting.secrets import AccessSecrets

PASSIVE_HUNTERS = {
    ApiServiceDiscovery,
    KubeDashboardDiscovery,
    EtcdRemoteAccessDiscovery,
    FromPodHostDiscovery,
    HostDiscovery,
    KubectlClientDiscovery,
    KubeletDiscovery,
    PortDiscovery,
    KubeProxyDiscovery,
    AzureSpnHunter,
    AccessApiServer,
    AccessApiServerWithToken,
    ApiVersionHunter,
    PodCapabilitiesHunter,
    CertificateDiscovery,
    KubernetesClusterCVEHunter,
    KubectlCVEHunter,
    KubeDashboard,
    EtcdRemoteAccess,
    ReadOnlyKubeletPortHunter,
    SecureKubeletPortHunter,
    VarLogMountHunter,
    KubeProxy,
    AccessSecrets,
}

ACTIVE_HUNTERS = {
    ProveAzureSpnExposure,
    AccessApiServerActive,
    ARPSpoofHunter,
    DNSSpoofHunter,
    EtcdRemoteAccessActive,
    ProveRunHandler,
    ProveContainerLogsHandler,
    ProveSystemLogs,
    ProveVarLogMount,
    ProveProxyExposed,
    K8sVersionDisclosureProve,
}


def test_type_filter():
    class Base:
        pass

    class Child(Base):
        pass

    expected = [Child]
    actual = type_filter([int, Child, str])

    assert expected == actual


def test_all_hunters():
    expected = PASSIVE_HUNTERS | ACTIVE_HUNTERS
    actual = all_hunters()

    assert expected == actual


def test_passive_hunters():
    expected = PASSIVE_HUNTERS
    actual = passive_hunters()

    assert expected == actual


def test_active_hunters():
    expected = ACTIVE_HUNTERS
    actual = active_hunters()

    assert expected == actual
