# flake8: noqa: E402
from kube_hunter.modules.discovery.hosts import (
    FromPodHostDiscovery,
    RunningAsPodEvent,
    HostScanEvent,
    HostDiscoveryHelpers,
)
from kube_hunter.core.types import Hunter
from kube_hunter.core.events.event_handler import handler
import json
import requests_mock
import pytest

from netaddr import IPNetwork, IPAddress
from typing import List
from kube_hunter.conf import Config, get_config, set_config

set_config(Config())


class TestFromPodHostDiscovery:
    @staticmethod
    def _make_azure_response(*subnets: List[tuple]) -> str:
        return json.dumps(
            {
                "network": {
                    "interface": [
                        {"ipv4": {"subnet": [{"address": address, "prefix": prefix} for address, prefix in subnets]}}
                    ]
                }
            }
        )

    @staticmethod
    def _make_aws_response(*data: List[str]) -> str:
        return "\n".join(data)

    def test_is_azure_pod_request_fail(self):
        f = FromPodHostDiscovery(RunningAsPodEvent())

        with requests_mock.Mocker() as m:
            m.get("http://169.254.169.254/metadata/instance?api-version=2017-08-01", status_code=404)
            result = f.is_azure_pod()

        assert not result

    def test_is_azure_pod_success(self):
        f = FromPodHostDiscovery(RunningAsPodEvent())

        with requests_mock.Mocker() as m:
            m.get(
                "http://169.254.169.254/metadata/instance?api-version=2017-08-01",
                text=TestFromPodHostDiscovery._make_azure_response(("3.4.5.6", "255.255.255.252")),
            )
            result = f.is_azure_pod()

        assert result

    def test_is_aws_pod_v1_request_fail(self):
        f = FromPodHostDiscovery(RunningAsPodEvent())

        with requests_mock.Mocker() as m:
            m.get("http://169.254.169.254/latest/meta-data/", status_code=404)
            result = f.is_aws_pod_v1()

        assert not result

    def test_is_aws_pod_v1_success(self):
        f = FromPodHostDiscovery(RunningAsPodEvent())

        with requests_mock.Mocker() as m:
            m.get(
                "http://169.254.169.254/latest/meta-data/",
                text=TestFromPodHostDiscovery._make_aws_response(
                    "\n".join(
                        (
                            "ami-id",
                            "ami-launch-index",
                            "ami-manifest-path",
                            "block-device-mapping/",
                            "events/",
                            "hostname",
                            "iam/",
                            "instance-action",
                            "instance-id",
                            "instance-type",
                            "local-hostname",
                            "local-ipv4",
                            "mac",
                            "metrics/",
                            "network/",
                            "placement/",
                            "profile",
                            "public-hostname",
                            "public-ipv4",
                            "public-keys/",
                            "reservation-id",
                            "security-groups",
                            "services/",
                        )
                    ),
                ),
            )
            result = f.is_aws_pod_v1()

        assert result

    def test_is_aws_pod_v2_request_fail(self):
        f = FromPodHostDiscovery(RunningAsPodEvent())

        with requests_mock.Mocker() as m:
            m.put(
                "http://169.254.169.254/latest/api/token/",
                headers={"X-aws-ec2-metatadata-token-ttl-seconds": "21600"},
                status_code=404,
            )
            m.get(
                "http://169.254.169.254/latest/meta-data/",
                headers={"X-aws-ec2-metatadata-token": "token"},
                status_code=404,
            )
            result = f.is_aws_pod_v2()

        assert not result

    def test_is_aws_pod_v2_success(self):
        f = FromPodHostDiscovery(RunningAsPodEvent())

        with requests_mock.Mocker() as m:
            m.put(
                "http://169.254.169.254/latest/api/token/",
                headers={"X-aws-ec2-metatadata-token-ttl-seconds": "21600"},
                text=TestFromPodHostDiscovery._make_aws_response("token"),
            )
            m.get(
                "http://169.254.169.254/latest/meta-data/",
                headers={"X-aws-ec2-metatadata-token": "token"},
                text=TestFromPodHostDiscovery._make_aws_response(
                    "\n".join(
                        (
                            "ami-id",
                            "ami-launch-index",
                            "ami-manifest-path",
                            "block-device-mapping/",
                            "events/",
                            "hostname",
                            "iam/",
                            "instance-action",
                            "instance-id",
                            "instance-type",
                            "local-hostname",
                            "local-ipv4",
                            "mac",
                            "metrics/",
                            "network/",
                            "placement/",
                            "profile",
                            "public-hostname",
                            "public-ipv4",
                            "public-keys/",
                            "reservation-id",
                            "security-groups",
                            "services/",
                        )
                    ),
                ),
            )
            result = f.is_aws_pod_v2()

        assert result

    def test_execute_scan_cidr(self):
        set_config(Config(cidr="1.2.3.4/30"))
        f = FromPodHostDiscovery(RunningAsPodEvent())
        f.execute()

    def test_execute_scan_remote(self):
        set_config(Config(remote="1.2.3.4"))
        f = FromPodHostDiscovery(RunningAsPodEvent())
        f.execute()


@handler.subscribe(HostScanEvent)
class HunterTestHostDiscovery(Hunter):
    """TestHostDiscovery
    In this set of tests we should only trigger HostScanEvent when remote or cidr are set
    """

    def __init__(self, event):
        config = get_config()
        assert config.remote is not None or config.cidr is not None
        assert config.remote == "1.2.3.4" or config.cidr == "1.2.3.4/30"


class TestDiscoveryUtils:
    @staticmethod
    def test_generate_hosts_valid_cidr():
        test_cidr = "192.168.0.0/24"
        expected = set(IPNetwork(test_cidr))

        actual = set(HostDiscoveryHelpers.generate_hosts([test_cidr]))

        assert actual == expected

    @staticmethod
    def test_generate_hosts_valid_ignore():
        remove = IPAddress("192.168.1.8")
        scan = "192.168.1.0/24"
        expected = {ip for ip in IPNetwork(scan) if ip != remove}

        actual = set(HostDiscoveryHelpers.generate_hosts([scan, f"!{str(remove)}"]))

        assert actual == expected

    @staticmethod
    def test_generate_hosts_invalid_cidr():
        with pytest.raises(ValueError):
            list(HostDiscoveryHelpers.generate_hosts(["192..2.3/24"]))

    @staticmethod
    def test_generate_hosts_invalid_ignore():
        with pytest.raises(ValueError):
            list(HostDiscoveryHelpers.generate_hosts(["192.168.1.8", "!29.2..1/24"]))
