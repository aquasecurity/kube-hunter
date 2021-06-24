from kube_hunter.conf import Config, set_config

from kube_hunter.modules.discovery.kubernetes_client import list_all_k8s_cluster_nodes
from unittest.mock import MagicMock, patch

set_config(Config())


def test_client_yields_ips():
    client = MagicMock()
    response = MagicMock()
    client.list_node.return_value = response
    response.items = [MagicMock(), MagicMock()]
    response.items[0].status.addresses = [MagicMock(), MagicMock()]
    response.items[0].status.addresses[0].address = "127.0.0.1"
    response.items[0].status.addresses[1].address = "127.0.0.2"
    response.items[1].status.addresses = [MagicMock()]
    response.items[1].status.addresses[0].address = "127.0.0.3"

    with patch("kubernetes.config.load_incluster_config") as m:
        output = list(list_all_k8s_cluster_nodes(client=client))
        m.assert_called_once()

    assert output == ["127.0.0.1", "127.0.0.2", "127.0.0.3"]


def test_client_uses_kubeconfig():
    with patch("kubernetes.config.load_kube_config") as m:
        list(list_all_k8s_cluster_nodes(kube_config="/location", client=MagicMock()))
        m.assert_called_once_with(config_file="/location")
