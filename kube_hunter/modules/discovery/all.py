from typing import List, Set, Type
from kube_hunter.core.types import Discovery
from . import (
    apiserver,
    dashboard,
    etcd,
    hosts,
    kubectl,
    kubelet,
    ports,
    proxy,
)

_discovery: Set[Type[Discovery]] = {
    apiserver.ApiServiceDiscovery,
    dashboard.KubeDashboard,
    etcd.EtcdRemoteAccess,
    hosts.HostDiscovery,
    hosts.FromPodHostDiscovery,
    kubectl.KubectlClientDiscovery,
    kubelet.KubeletDiscovery,
    ports.PortDiscovery,
    proxy.KubeProxy,
}


def all_discovery() -> List[Type[Discovery]]:
    return list(_discovery)
