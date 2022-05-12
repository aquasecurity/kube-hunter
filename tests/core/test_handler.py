# flake8: noqa: E402

from kube_hunter.conf import Config, set_config, get_config

set_config(Config(active=True))

from kube_hunter.core.events.event_handler import handler
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
from kube_hunter.modules.hunting.capabilities import PodCapabilitiesHunter
from kube_hunter.modules.hunting.certificates import CertificateDiscovery

from kube_hunter.modules.hunting.cves import K8sClusterCveHunter
from kube_hunter.modules.hunting.cves import KubectlCVEHunter
from kube_hunter.modules.hunting.dashboard import KubeDashboard
from kube_hunter.modules.hunting.etcd import EtcdRemoteAccess, EtcdRemoteAccessActive
from kube_hunter.modules.hunting.kubelet import (
    ProveAnonymousAuth,
    MaliciousIntentViaSecureKubeletPort,
    ProveContainerLogsHandler,
    ProveRunHandler,
    ProveSystemLogs,
    ReadOnlyKubeletPortHunter,
    SecureKubeletPortHunter,
)
from kube_hunter.modules.hunting.mounts import VarLogMountHunter, ProveVarLogMount
from kube_hunter.modules.hunting.proxy import KubeProxy, ProveProxyExposed, K8sVersionDisclosureProve
from kube_hunter.modules.hunting.secrets import AccessSecrets

config = get_config()

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
    KubectlCVEHunter,
    KubeDashboard,
    EtcdRemoteAccess,
    ReadOnlyKubeletPortHunter,
    SecureKubeletPortHunter,
    VarLogMountHunter,
    KubeProxy,
    AccessSecrets,
}

# if config.enable_cve_hunting:
#     PASSIVE_HUNTERS.append(K8sClusterCveHunter)

ACTIVE_HUNTERS = {
    ProveAzureSpnExposure,
    AccessApiServerActive,
    EtcdRemoteAccessActive,
    ProveRunHandler,
    ProveContainerLogsHandler,
    ProveSystemLogs,
    ProveVarLogMount,
    ProveProxyExposed,
    K8sVersionDisclosureProve,
    ProveAnonymousAuth,
    MaliciousIntentViaSecureKubeletPort,
}


def remove_test_hunters(hunters):
    return {hunter for hunter in hunters if not hunter.__module__.startswith("test")}


def test_passive_hunters_registered():
    expected_missing = set()
    expected_odd = set()

    registered_passive = remove_test_hunters(handler.passive_hunters.keys())
    actual_missing = PASSIVE_HUNTERS - registered_passive
    actual_odd = registered_passive - PASSIVE_HUNTERS

    assert expected_missing == actual_missing, "Passive hunters are missing"
    assert expected_odd == actual_odd, "Unexpected passive hunters are registered"


def test_active_hunters_registered():
    expected_missing = set()
    expected_odd = set()

    registered_active = remove_test_hunters(handler.active_hunters.keys())
    actual_missing = ACTIVE_HUNTERS - registered_active
    actual_odd = registered_active - ACTIVE_HUNTERS

    assert expected_missing == actual_missing, "Active hunters are missing"
    assert expected_odd == actual_odd, "Unexpected active hunters are registered"


def test_all_hunters_registered():
    expected = PASSIVE_HUNTERS | ACTIVE_HUNTERS
    actual = remove_test_hunters(handler.all_hunters.keys())

    assert expected == actual
