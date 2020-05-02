from typing import Iterable, List, Set, Type
from kube_hunter.core.types import ActiveHunter, Hunter, HunterBase
from . import (
    aks,
    apiserver,
    arp,
    capabilities,
    certificates,
    cves,
    dashboard,
    dns,
    etcd,
    kubelet,
    mounts,
    proxy,
    secrets,
)

_hunters: Set[Type[HunterBase]] = {
    aks.AzureSpnHunter,
    aks.ProveAzureSpnExposure,
    apiserver.AccessApiServer,
    apiserver.AccessApiServerActive,
    apiserver.ApiVersionHunter,
    arp.ARPSpoofHunter,
    capabilities.PodCapabilitiesHunter,
    certificates.CertificateDiscovery,
    cves.KubernetesClusterCVEHunter,
    cves.KubectlCVEHunter,
    dashboard.KubeDashboard,
    dns.DNSSpoofHunter,
    etcd.EtcdRemoteAccess,
    etcd.EtcdRemoteAccessActive,
    kubelet.ReadOnlyKubeletPortHunter,
    kubelet.SecureKubeletPortHunter,
    kubelet.ProveRunHandler,
    kubelet.ProveContainerLogsHandler,
    kubelet.ProveSystemLogs,
    mounts.VarLogMountHunter,
    mounts.ProveVarLogMount,
    proxy.KubeProxy,
    proxy.ProveProxyExposed,
    proxy.K8sVersionDisclosureProve,
    secrets.AccessSecrets,
}


def type_filter(items: Iterable[type], selected: type):
    return [item for item in items if issubclass(item, selected)]


def all_hunters() -> List[Type[HunterBase]]:
    return list(_hunters)


def passive_hunters() -> List[Type[HunterBase]]:
    return type_filter(_hunters, Hunter)


def active_hunters() -> List[Type[HunterBase]]:
    return type_filter(_hunters, ActiveHunter)
