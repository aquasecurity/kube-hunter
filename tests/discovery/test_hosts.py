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
    def test_is_aws_metadata_v1_fail():
        """
        Test that the aws_metadata_v1_discovery returns the expected response when
        the CIDR returns 404 from the url.
        """
        f = FromPodHostDiscovery(RunningAsPodEvent())
        expected_result = ([], "AWS")
        with requests_mock.Mocker() as m:
            m.get(
                "http://169.254.169.254/latest/meta-data/mac",
                text="39-14-C3-2C-5D-59"),
            m.get(
                "http://169.254.169.254/latest/meta-data/network/interfaces/macs/"
                "39-14-C3-2C-5D-59/subnet-ipv4-cidr-block",
                text="<head><title>404 Not Found</title></head",
                status_code=404
            )
            result = f.aws_metadata_v1_discovery()
        assert result == expected_result

    @staticmethod
    def test_is_aws_metadata_v1_fail_again():
        """
        Test that the aws_metadata_v1_discovery returns the expected response when
        the CIDR is in an incorrect structure.
        """
        f = FromPodHostDiscovery(RunningAsPodEvent())
        expected_result = ([], "AWS")
        with requests_mock.Mocker() as m:
            m.get(
                "http://169.254.169.254/latest/meta-data/mac",
                text="39-14-C3-2C-5D-59"),
            m.get(
                ("http://169.254.169.254/latest/meta-data/network/interfaces/macs/39-14-C3-2C-5D-59/"
                 "subnet-ipv4-cidr-block"),
                text="1.1.1.3/23.23",
                status_code=200
            )
            result = f.aws_metadata_v1_discovery()

        assert result == expected_result

    @staticmethod
    def test_is_aws_metadata_v1_pass():
        """
        Test that the aws_metadata_v1_discovery returns the expected response when
        the CIDR is in the correct structure.
        """
        f = FromPodHostDiscovery(RunningAsPodEvent())
        expected_result = ([('1.1.1.3', '23')], 'AWS')
        with requests_mock.Mocker() as m:
            m.get(
                "http://169.254.169.254/latest/meta-data/mac",
                headers={"X-aws-ec2-metatadata-token-ttl-seconds": "21600"},
                text="39-14-C3-2C-5D-59")
            m.get(
                "http://169.254.169.254/latest/meta-data/network/interfaces/"
                "macs/39-14-C3-2C-5D-59/subnet-ipv4-cidr-block",
                text="1.1.1.3/23",
                status_code=200
            )
            result = f.aws_metadata_v1_discovery()

        assert result == expected_result

    @staticmethod
    def test_is_aws_metadata_v2_pass():
        """
        Test that the aws_metadata_v2_discovery returns the expected response when
        the CIDR is in the correct structure.
        """
        f = FromPodHostDiscovery(RunningAsPodEvent())
        expected_result = ([('1.1.1.1', '23')], 'AWS')
        with requests_mock.Mocker() as m:
            m.get(
                "http://169.254.169.254/latest/api/token",
                headers={"X-aws-ec2-metatadata-token-ttl-seconds": "21600"},
                text='random-generated-token')
            m.get(
                "http://169.254.169.254/latest/meta-data/mac",
                headers={"X-aws-ec2-metatadata-token": 'random-generated-token'},
                text="39-14-C3-2C-5D-59")
            m.get(
                "http://169.254.169.254/latest/meta-data/network/"
                f"interfaces/macs/39-14-C3-2C-5D-59/subnet-ipv4-cidr-block",
                headers={"X-aws-ec2-metatadata-token": 'random-generated-token'},
                text="1.1.1.1/23")
            result = f.aws_metadata_v2_discovery()

        assert result == expected_result

    @staticmethod
    def test_is_aws_metadata_v2_fail_incorrect_structure():
        """
        Test that the aws_metadata_v2_discovery returns the expected response when
        the CIDR is in an incorrect structure.
        """
        f = FromPodHostDiscovery(RunningAsPodEvent())
        expected_result = ([], 'AWS')
        with requests_mock.Mocker() as m:
            m.get(
                "http://169.254.169.254/latest/api/token",
                headers={"X-aws-ec2-metatadata-token-ttl-seconds": "21600"},
                text='random-generated-token')
            m.get(
                "http://169.254.169.254/latest/meta-data/mac",
                headers={"X-aws-ec2-metatadata-token": 'random-generated-token'},
                text="39-14-C3-2C-5D-59")
            m.get(
                "http://169.254.169.254/latest/meta-data/network/"
                f"interfaces/macs/39-14-C3-2C-5D-59/subnet-ipv4-cidr-block",
                headers={"X-aws-ec2-metatadata-token": 'random-generated-token'},
                text="1.1.1.1/23.23")
            result = f.aws_metadata_v2_discovery()

        assert result == expected_result

    @staticmethod
    def test_is_aws_metadata_v2_fail_cidr_not_found():
        """
        Test that the aws_metadata_v2_discovery returns the expected response when
        the CIDR returns 404 from the url.
        """
        f = FromPodHostDiscovery(RunningAsPodEvent())
        expected_result = ([], 'AWS')
        with requests_mock.Mocker() as m:
            m.get(
                "http://169.254.169.254/latest/api/token",
                headers={"X-aws-ec2-metatadata-token-ttl-seconds": "21600"},
                text='random-generated-token')
            m.get(
                "http://169.254.169.254/latest/meta-data/mac",
                headers={"X-aws-ec2-metatadata-token": 'random-generated-token'},
                text="39-14-C3-2C-5D-59")
            m.get(
                "http://169.254.169.254/latest/meta-data/network/"
                f"interfaces/macs/39-14-C3-2C-5D-59/subnet-ipv4-cidr-block",
                headers={"X-aws-ec2-metatadata-token": 'random-generated-token'},
                text="<head><title>404 Not Found</title></head")
            result = f.aws_metadata_v2_discovery()

        assert result == expected_result

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
