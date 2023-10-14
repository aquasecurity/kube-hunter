# flake8: noqa: E402

from kube_hunter.conf import Config, set_config

set_config(Config())

from kube_hunter.modules.discovery.kubectl import KubectlClientDiscovery


def test_kubectl_discovery():
    discovery = KubectlClientDiscovery(None)
    version = discovery.get_kubectl_binary_version()
    assert version is not None
