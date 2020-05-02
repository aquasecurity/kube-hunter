# flake8: noqa: E402
import time

from kube_hunter.conf import Config, set_config
from kube_hunter.core.events import K8sVersionDisclosure
from kube_hunter.modules.hunting.cves import (
    CVEUtils,
    IncompleteFixToKubectlCpVulnerability,
    KubectlClientFound,
    KubectlCpVulnerability,
    KubectlCVEHunter,
    KubernetesClusterCVEHunter,
    PingFloodHTTP2,
    ResetFloodHTTP2,
    ServerApiClusterScopedResourcesAccess,
    ServerApiVersionEndPointAccessDos,
    ServerApiVersionEndPointAccessPE,
)


class TestKubectlCVEHunter:
    def test_execute_no_patches(self):
        test_cases = (
            ("1.11.0", [IncompleteFixToKubectlCpVulnerability, KubectlCpVulnerability]),
            ("1.11.9", [IncompleteFixToKubectlCpVulnerability]),
            ("1.12.3", [IncompleteFixToKubectlCpVulnerability, KubectlCpVulnerability]),
            ("1.12.10", []),
            ("1.13.4", [IncompleteFixToKubectlCpVulnerability, KubectlCpVulnerability]),
            ("1.13.5", [IncompleteFixToKubectlCpVulnerability]),
            ("1.13.6", []),
            ("1.14.0", [IncompleteFixToKubectlCpVulnerability]),
            ("1.14.2", []),
            ("1.11.0-vendor", []),
            ("1.11.9-vendor", []),
            ("1.12.3-vendor", []),
            ("1.12.10-vendor", []),
            ("1.13.4-vendor", []),
            ("1.13.5-vendor", []),
            ("1.13.6-vendor", []),
            ("1.14.0-vendor", []),
            ("1.14.2-vendor", []),
        )

        set_config(Config())

        for version, expected in test_cases:
            hunter = KubectlCVEHunter(KubectlClientFound(version))
            actual = {type(event) for event in hunter.execute()}

            assert set(expected) == actual

    def test_execute_with_patches(self):
        test_cases = (
            ("1.11.0-vendor", [IncompleteFixToKubectlCpVulnerability, KubectlCpVulnerability]),
            ("1.11.9-vendor", [IncompleteFixToKubectlCpVulnerability]),
            ("1.12.3-vendor", [IncompleteFixToKubectlCpVulnerability, KubectlCpVulnerability]),
            ("1.12.10-vendor", []),
            ("1.13.4-vendor", [IncompleteFixToKubectlCpVulnerability, KubectlCpVulnerability]),
            ("1.13.5-vendor", [IncompleteFixToKubectlCpVulnerability]),
            ("1.13.6-vendor", []),
            ("1.14.0-vendor", [IncompleteFixToKubectlCpVulnerability]),
            ("1.14.2-vendor", []),
        )

        set_config(Config(include_patched_versions=True))

        for version, expected in test_cases:
            hunter = KubectlCVEHunter(KubectlClientFound(version))
            actual = {type(event) for event in hunter.execute()}

            assert set(expected) == actual


class TestKubernetesClusterCVEHunter:
    def test_execute_no_patches(self):
        test_cases = (
            (
                "1.10.0",
                [
                    ServerApiVersionEndPointAccessPE,
                    ServerApiVersionEndPointAccessDos,
                    ResetFloodHTTP2,
                    PingFloodHTTP2,
                    ServerApiClusterScopedResourcesAccess,
                ],
            ),
            (
                "1.10.11",
                [
                    ServerApiVersionEndPointAccessDos,
                    ResetFloodHTTP2,
                    PingFloodHTTP2,
                    ServerApiClusterScopedResourcesAccess,
                ],
            ),
            (
                "1.11.3",
                [
                    ServerApiVersionEndPointAccessPE,
                    ServerApiVersionEndPointAccessDos,
                    ResetFloodHTTP2,
                    PingFloodHTTP2,
                    ServerApiClusterScopedResourcesAccess,
                ],
            ),
            (
                "1.11.5",
                [
                    ServerApiVersionEndPointAccessDos,
                    ResetFloodHTTP2,
                    PingFloodHTTP2,
                    ServerApiClusterScopedResourcesAccess,
                ],
            ),
            ("1.11.8", [ResetFloodHTTP2, PingFloodHTTP2, ServerApiClusterScopedResourcesAccess]),
            (
                "1.12.2",
                [
                    ServerApiVersionEndPointAccessPE,
                    ServerApiVersionEndPointAccessDos,
                    ResetFloodHTTP2,
                    PingFloodHTTP2,
                    ServerApiClusterScopedResourcesAccess,
                ],
            ),
            (
                "1.12.3",
                [
                    ServerApiVersionEndPointAccessDos,
                    ResetFloodHTTP2,
                    PingFloodHTTP2,
                    ServerApiClusterScopedResourcesAccess,
                ],
            ),
            ("1.12.6", [ResetFloodHTTP2, PingFloodHTTP2, ServerApiClusterScopedResourcesAccess]),
            (
                "1.13.3",
                [
                    ServerApiVersionEndPointAccessDos,
                    ResetFloodHTTP2,
                    PingFloodHTTP2,
                    ServerApiClusterScopedResourcesAccess,
                ],
            ),
            ("1.13.4", [ResetFloodHTTP2, PingFloodHTTP2, ServerApiClusterScopedResourcesAccess]),
            ("1.13.9", [ResetFloodHTTP2, PingFloodHTTP2]),
            ("1.13.10", []),
            ("1.14.4", [ResetFloodHTTP2, PingFloodHTTP2, ServerApiClusterScopedResourcesAccess]),
            ("1.14.5", [ResetFloodHTTP2, PingFloodHTTP2]),
            ("1.14.6", []),
            ("1.15.1", [ResetFloodHTTP2, PingFloodHTTP2, ServerApiClusterScopedResourcesAccess]),
            ("1.15.2", [ResetFloodHTTP2, PingFloodHTTP2]),
            ("1.15.3", []),
            ("1.10.0-vendor", []),
            ("1.10.11-vendor", []),
            ("1.11.3-vendor", []),
            ("1.11.5-vendor", []),
            ("1.11.8-vendor", []),
            ("1.12.2-vendor", []),
            ("1.12.3-vendor", []),
            ("1.12.6-vendor", []),
            ("1.13.3-vendor", []),
            ("1.13.4-vendor", []),
            ("1.13.9-vendor", []),
            ("1.13.10-vendor", []),
            ("1.14.4-vendor", []),
            ("1.14.5-vendor", []),
            ("1.14.6-vendor", []),
            ("1.15.1-vendor", []),
            ("1.15.2-vendor", []),
            ("1.15.3-vendor", []),
        )

        set_config(Config())

        for version, expected in test_cases:
            hunter = KubernetesClusterCVEHunter(K8sVersionDisclosure(version, from_endpoint="/version"))
            actual = {type(event) for event in hunter.execute()}

            assert set(expected) == actual

    def test_execute_with_patches(self):
        test_cases = (
            (
                "1.10.0-vendor",
                [
                    ServerApiVersionEndPointAccessPE,
                    ServerApiVersionEndPointAccessDos,
                    ResetFloodHTTP2,
                    PingFloodHTTP2,
                    ServerApiClusterScopedResourcesAccess,
                ],
            ),
            (
                "1.10.11-vendor",
                [
                    ServerApiVersionEndPointAccessDos,
                    ResetFloodHTTP2,
                    PingFloodHTTP2,
                    ServerApiClusterScopedResourcesAccess,
                ],
            ),
            (
                "1.11.3-vendor",
                [
                    ServerApiVersionEndPointAccessPE,
                    ServerApiVersionEndPointAccessDos,
                    ResetFloodHTTP2,
                    PingFloodHTTP2,
                    ServerApiClusterScopedResourcesAccess,
                ],
            ),
            (
                "1.11.5-vendor",
                [
                    ServerApiVersionEndPointAccessDos,
                    ResetFloodHTTP2,
                    PingFloodHTTP2,
                    ServerApiClusterScopedResourcesAccess,
                ],
            ),
            ("1.11.8-vendor", [ResetFloodHTTP2, PingFloodHTTP2, ServerApiClusterScopedResourcesAccess]),
            (
                "1.12.2-vendor",
                [
                    ServerApiVersionEndPointAccessPE,
                    ServerApiVersionEndPointAccessDos,
                    ResetFloodHTTP2,
                    PingFloodHTTP2,
                    ServerApiClusterScopedResourcesAccess,
                ],
            ),
            (
                "1.12.3-vendor",
                [
                    ServerApiVersionEndPointAccessDos,
                    ResetFloodHTTP2,
                    PingFloodHTTP2,
                    ServerApiClusterScopedResourcesAccess,
                ],
            ),
            ("1.12.6-vendor", [ResetFloodHTTP2, PingFloodHTTP2, ServerApiClusterScopedResourcesAccess]),
            (
                "1.13.3-vendor",
                [
                    ServerApiVersionEndPointAccessDos,
                    ResetFloodHTTP2,
                    PingFloodHTTP2,
                    ServerApiClusterScopedResourcesAccess,
                ],
            ),
            ("1.13.4-vendor", [ResetFloodHTTP2, PingFloodHTTP2, ServerApiClusterScopedResourcesAccess]),
            ("1.13.9-vendor", [ResetFloodHTTP2, PingFloodHTTP2]),
            ("1.13.10-vendor", []),
            ("1.14.4-vendor", [ResetFloodHTTP2, PingFloodHTTP2, ServerApiClusterScopedResourcesAccess]),
            ("1.14.5-vendor", [ResetFloodHTTP2, PingFloodHTTP2]),
            ("1.14.6-vendor", []),
            ("1.15.1-vendor", [ResetFloodHTTP2, PingFloodHTTP2, ServerApiClusterScopedResourcesAccess]),
            ("1.15.2-vendor", [ResetFloodHTTP2, PingFloodHTTP2]),
            ("1.15.3-vendor", []),
        )

        set_config(Config(include_patched_versions=True))

        for version, expected in test_cases:
            hunter = KubernetesClusterCVEHunter(K8sVersionDisclosure(version, from_endpoint="/version"))
            actual = {type(event) for event in hunter.execute()}

            assert set(expected) == actual


class TestCVEUtils:
    def test_is_downstream(self):
        test_cases = (
            ("1", False),
            ("1.2", False),
            ("1.2-3", True),
            ("1.2-r3", True),
            ("1.2+3", True),
            ("1.2~3", True),
            ("1.2+a3f5cb2", True),
            ("1.2-9287543", True),
            ("v1", False),
            ("v1.2", False),
            ("v1.2-3", True),
            ("v1.2-r3", True),
            ("v1.2+3", True),
            ("v1.2~3", True),
            ("v1.2+a3f5cb2", True),
            ("v1.2-9287543", True),
            ("v1.13.9-gke.3", True),
        )

        for version, expected in test_cases:
            actual = CVEUtils.is_downstream_version(version)
            assert actual == expected

    def test_ignore_downstream(self):
        test_cases = (
            ("v2.2-abcd", ["v1.1", "v2.3"], False),
            ("v2.2-abcd", ["v1.1", "v2.2"], False),
            ("v1.13.9-gke.3", ["v1.14.8"], False),
        )

        for check_version, fix_versions, expected in test_cases:
            actual = CVEUtils.is_vulnerable(fix_versions, check_version, True)
            assert actual == expected
