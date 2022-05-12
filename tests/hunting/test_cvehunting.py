# flake8: noqa: E402
import time

from kube_hunter.conf import Config, set_config

set_config(Config())

from kube_hunter.core.events.event_handler import handler
from kube_hunter.core.events.types import K8sVersionDisclosure
from kube_hunter.modules.hunting.cves import (
    K8sClusterCveHunter,
    ServerApiVersionEndPointAccessPE,
    ServerApiVersionEndPointAccessDos,
    CveUtils,
)

cve_counter = 0


def test_K8sCveHunter():
    global cve_counter
    # because the hunter unregisters itself, we manually remove this option, so we can test it
    K8sClusterCveHunter.__new__ = lambda self, cls: object.__new__(self)

    e = K8sVersionDisclosure(version="1.10.1", from_endpoint="/version")
    h = K8sClusterCveHunter(e)
    h.execute()

    time.sleep(0.01)
    assert cve_counter == 2
    cve_counter = 0

    # test patched version
    e = K8sVersionDisclosure(version="v1.13.6-gke.13", from_endpoint="/version")
    h = K8sClusterCveHunter(e)
    h.execute()

    time.sleep(0.01)
    assert cve_counter == 0
    cve_counter = 0


@handler.subscribe(ServerApiVersionEndPointAccessPE)
class test_CVE_2018_1002105:
    def __init__(self, event):
        global cve_counter
        cve_counter += 1


@handler.subscribe(ServerApiVersionEndPointAccessDos)
class test_CVE_2019_1002100:
    def __init__(self, event):
        global cve_counter
        cve_counter += 1


class TestCveUtils:
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
            actual = CveUtils.is_downstream_version(version)
            assert actual == expected

    def test_ignore_downstream(self):
        test_cases = (
            ("v2.2-abcd", ["v1.1", "v2.3"], False),
            ("v2.2-abcd", ["v1.1", "v2.2"], False),
            ("v1.13.9-gke.3", ["v1.14.8"], False),
        )

        for check_version, fix_versions, expected in test_cases:
            actual = CveUtils.is_vulnerable(fix_versions, check_version, True)
            assert actual == expected
