import json
import os
import sys
import socket
import logging
import itertools
import requests

from enum import Enum
from netaddr import IPNetwork, IPAddress, AddrFormatError

from kube_hunter.conf import get_config
from kube_hunter.modules.discovery.kubernetes_client import list_all_k8s_cluster_nodes
from kube_hunter.core.events.event_handler import handler
from kube_hunter.core.events.types import Event, NewHostEvent, Vulnerability
from kube_hunter.core.types import Discovery, AWS, Azure, InstanceMetadataApiTechnique

logger = logging.getLogger(__name__)


class RunningAsPodEvent(Event):
    def __init__(self):
        self.name = "Running from within a pod"
        self.client_cert = self.get_service_account_file("ca.crt")
        self.namespace = self.get_service_account_file("namespace")
        self.kubeservicehost = os.environ.get("KUBERNETES_SERVICE_HOST", None)

        # if service account token was manually specified, we don't load the token file
        config = get_config()
        if config.service_account_token:
            self.auth_token = config.service_account_token
        else:
            self.auth_token = self.get_service_account_file("token")

    # Event's logical location to be used mainly for reports.
    def location(self):
        location = "Local to Pod"
        hostname = os.getenv("HOSTNAME")
        if hostname:
            location += f" ({hostname})"

        return location

    def get_service_account_file(self, file):
        try:
            with open(f"/var/run/secrets/kubernetes.io/serviceaccount/{file}") as f:
                return f.read()
        except OSError:
            pass


class AWSMetadataApi(Vulnerability, Event):
    """Access to the AWS Metadata API exposes information about the machines associated with the cluster"""

    def __init__(self, cidr):
        Vulnerability.__init__(
            self,
            AWS,
            "AWS Metadata Exposure",
            category=InstanceMetadataApiTechnique,
            vid="KHV053",
        )
        self.cidr = cidr
        self.evidence = f"cidr: {cidr}"


class AzureMetadataApi(Vulnerability, Event):
    """Access to the Azure Metadata API exposes information about the machines associated with the cluster"""

    def __init__(self, cidr):
        Vulnerability.__init__(
            self,
            Azure,
            "Azure Metadata Exposure",
            category=InstanceMetadataApiTechnique,
            vid="KHV003",
        )
        self.cidr = cidr
        self.evidence = f"cidr: {cidr}"


class HostScanEvent(Event):
    def __init__(self, pod=False, active=False, predefined_hosts=None):
        # flag to specify whether to get actual data from vulnerabilities
        self.active = active
        self.predefined_hosts = predefined_hosts or []


class HostDiscoveryHelpers:
    # generator, generating a subnet by given a cidr
    @staticmethod
    def filter_subnet(subnet, ignore=None):
        for ip in subnet:
            if ignore and any(ip in s for s in ignore):
                logger.debug(f"HostDiscoveryHelpers.filter_subnet ignoring {ip}")
            else:
                yield ip

    @staticmethod
    def generate_hosts(cidrs):
        ignore = list()
        scan = list()
        for cidr in cidrs:
            try:
                if cidr.startswith("!"):
                    ignore.append(IPNetwork(cidr[1:]))
                else:
                    scan.append(IPNetwork(cidr))
            except AddrFormatError as e:
                raise ValueError(f"Unable to parse CIDR {cidr}") from e

        return itertools.chain.from_iterable(HostDiscoveryHelpers.filter_subnet(sb, ignore=ignore) for sb in scan)


@handler.subscribe(RunningAsPodEvent)
class FromPodHostDiscovery(Discovery):
    """Host Discovery when running as pod
    Generates ip adresses to scan, based on cluster/scan type
    """

    def __init__(self, event):
        self.event = event

    def execute(self):
        config = get_config()
        # Attempt to read all hosts from the Kubernetes API
        for host in list_all_k8s_cluster_nodes(config.kubeconfig):
            self.publish_event(NewHostEvent(host=host))
        # Scan any hosts that the user specified
        if config.remote or config.cidr:
            self.publish_event(HostScanEvent())
        else:
            # Discover cluster subnets, we'll scan all these hosts
            cloud, subnets = None, list()
            if self.is_azure_pod():
                subnets, cloud = self.azure_metadata_discovery()
            elif self.is_aws_pod_v1():
                subnets, cloud = self.aws_metadata_v1_discovery()
            elif self.is_aws_pod_v2():
                subnets, cloud = self.aws_metadata_v2_discovery()

            gateway_subnet = self.gateway_discovery()
            if gateway_subnet:
                subnets.append(gateway_subnet)

            should_scan_apiserver = False
            if self.event.kubeservicehost:
                should_scan_apiserver = True
            for ip, mask in subnets:
                if self.event.kubeservicehost and self.event.kubeservicehost in IPNetwork(f"{ip}/{mask}"):
                    should_scan_apiserver = False
                logger.debug(f"From pod scanning subnet {ip}/{mask}")
                for ip in IPNetwork(f"{ip}/{mask}"):
                    self.publish_event(NewHostEvent(host=ip, cloud=cloud))
            if should_scan_apiserver:
                self.publish_event(NewHostEvent(host=IPAddress(self.event.kubeservicehost), cloud=cloud))

    def is_aws_pod_v1(self):
        config = get_config()
        try:
            # Instance Metadata Service v1
            logger.debug("From pod attempting to access AWS Metadata v1 API")
            if (
                requests.get(
                    "http://169.254.169.254/latest/meta-data/",
                    timeout=config.network_timeout,
                ).status_code
                == 200
            ):
                return True
        except requests.exceptions.ConnectionError:
            logger.debug("Failed to connect AWS metadata server v1")
        except Exception:
            logger.debug("Unknown error when trying to connect to AWS metadata v1 API")
        return False

    def is_aws_pod_v2(self):
        config = get_config()
        try:
            # Instance Metadata Service v2
            logger.debug("From pod attempting to access AWS Metadata v2 API")
            token = requests.put(
                "http://169.254.169.254/latest/api/token/",
                headers={"X-aws-ec2-metatadata-token-ttl-seconds": "21600"},
                timeout=config.network_timeout,
            ).text
            if (
                requests.get(
                    "http://169.254.169.254/latest/meta-data/",
                    headers={"X-aws-ec2-metatadata-token": token},
                    timeout=config.network_timeout,
                ).status_code
                == 200
            ):
                return True
        except requests.exceptions.ConnectionError:
            logger.debug("Failed to connect AWS metadata server v2")
        except Exception:
            logger.debug("Unknown error when trying to connect to AWS metadata v2 API")
        return False

    def is_azure_pod(self):
        config = get_config()
        try:
            logger.debug("From pod attempting to access Azure Metadata API")
            if (
                requests.get(
                    "http://169.254.169.254/metadata/instance?api-version=2017-08-01",
                    headers={"Metadata": "true"},
                    timeout=config.network_timeout,
                ).status_code
                == 200
            ):
                return True
        except requests.exceptions.ConnectionError:
            logger.debug("Failed to connect Azure metadata server")
        except Exception:
            logger.debug("Unknown error when trying to connect to Azure metadata server")
        return False

    # for pod scanning
    def gateway_discovery(self):
        """Retrieving default gateway of pod, which is usually also a contact point with the host"""
        # read the default gateway directly from /proc
        # netifaces currently does not have a maintainer. so we backported to linux support only for this cause.
        # TODO: implement WMI queries for windows support
        # https://stackoverflow.com/a/6556951
        if sys.platform in ["linux", "linux2"]:
            try:
                from pyroute2 import IPDB

                ip = IPDB()
                gateway_ip = ip.routes["default"]["gateway"]
                ip.release()
                return [gateway_ip, "24"]
            except Exception as x:
                logging.debug(f"Exception while fetching default gateway from container - {x}")
            finally:
                ip.release()
        else:
            logging.debug("Not running in a linux env, will not scan default subnet")

        return False

    # querying AWS's interface metadata api v1 | works only from a pod
    def aws_metadata_v1_discovery(self):
        config = get_config()
        logger.debug("From pod attempting to access aws's metadata v1")
        mac_address = requests.get(
            "http://169.254.169.254/latest/meta-data/mac",
            timeout=config.network_timeout,
        ).text
        logger.debug(f"Extracted mac from aws's metadata v1: {mac_address}")

        cidr = requests.get(
            f"http://169.254.169.254/latest/meta-data/network/interfaces/macs/{mac_address}/subnet-ipv4-cidr-block",
            timeout=config.network_timeout,
        ).text
        logger.debug(f"Trying to extract cidr from aws's metadata v1: {cidr}")

        try:
            cidr = cidr.split("/")
            address, subnet = (cidr[0], cidr[1])
            subnet = subnet if not config.quick else "24"
            cidr = f"{address}/{subnet}"
            logger.debug(f"From pod discovered subnet {cidr}")

            self.publish_event(AWSMetadataApi(cidr=cidr))
            return [(address, subnet)], "AWS"
        except Exception as x:
            logger.debug(f"ERROR: could not parse cidr from aws metadata api: {cidr} - {x}")

        return [], "AWS"

    # querying AWS's interface metadata api v2 | works only from a pod
    def aws_metadata_v2_discovery(self):
        config = get_config()
        logger.debug("From pod attempting to access aws's metadata v2")
        token = requests.get(
            "http://169.254.169.254/latest/api/token",
            headers={"X-aws-ec2-metatadata-token-ttl-seconds": "21600"},
            timeout=config.network_timeout,
        ).text
        mac_address = requests.get(
            "http://169.254.169.254/latest/meta-data/mac",
            headers={"X-aws-ec2-metatadata-token": token},
            timeout=config.network_timeout,
        ).text
        cidr = requests.get(
            f"http://169.254.169.254/latest/meta-data/network/interfaces/macs/{mac_address}/subnet-ipv4-cidr-block",
            headers={"X-aws-ec2-metatadata-token": token},
            timeout=config.network_timeout,
        ).text.split("/")

        try:
            address, subnet = (cidr[0], cidr[1])
            subnet = subnet if not config.quick else "24"
            cidr = f"{address}/{subnet}"
            logger.debug(f"From pod discovered subnet {cidr}")

            self.publish_event(AWSMetadataApi(cidr=cidr))

            return [(address, subnet)], "AWS"
        except Exception as x:
            logger.debug(f"ERROR: could not parse cidr from aws metadata api: {cidr} - {x}")

        return [], "AWS"

    # querying azure's interface metadata api | works only from a pod
    def azure_metadata_discovery(self):
        config = get_config()
        logger.debug("From pod attempting to access azure's metadata")
        machine_metadata = requests.get(
            "http://169.254.169.254/metadata/instance?api-version=2017-08-01",
            headers={"Metadata": "true"},
            timeout=config.network_timeout,
        ).json()
        address, subnet = "", ""
        subnets = list()
        for interface in machine_metadata["network"]["interface"]:
            address, subnet = (
                interface["ipv4"]["subnet"][0]["address"],
                interface["ipv4"]["subnet"][0]["prefix"],
            )
            subnet = subnet if not config.quick else "24"
            logger.debug(f"From pod discovered subnet {address}/{subnet}")
            subnets.append([address, subnet if not config.quick else "24"])

            self.publish_event(AzureMetadataApi(cidr=f"{address}/{subnet}"))

        return subnets, "Azure"


@handler.subscribe(HostScanEvent)
class HostDiscovery(Discovery):
    """Host Discovery
    Generates ip adresses to scan, based on cluster/scan type
    """

    def __init__(self, event):
        self.event = event

    def execute(self):
        config = get_config()
        if config.cidr:
            for ip in HostDiscoveryHelpers.generate_hosts(config.cidr):
                self.publish_event(NewHostEvent(host=ip))
        elif config.interface:
            self.scan_interfaces()
        elif len(config.remote) > 0:
            for host in config.remote:
                self.publish_event(NewHostEvent(host=host))
        elif config.k8s_auto_discover_nodes:
            for host in list_all_k8s_cluster_nodes(config.kubeconfig):
                self.publish_event(NewHostEvent(host=host))

    # for normal scanning
    def scan_interfaces(self):
        for ip in self.generate_interfaces_subnet():
            handler.publish_event(NewHostEvent(host=ip))

    # generate all subnets from all internal network interfaces
    def generate_interfaces_subnet(self, sn="24"):
        if sys.platform == "win32":
            return self.generate_interfaces_subnet_windows()
        elif sys.platform in ["linux", "linux2"]:
            return self.generate_interfaces_subnet_linux()

    def generate_interfaces_subnet_linux(self, sn="24"):
        try:
            from pyroute2 import IPRoute

            ip = IPRoute()
            for i in ip.get_addr():
                # whitelist only ipv4 ips
                if i["family"] == socket.AF_INET:
                    ipaddress = i[0].get_attr("IFA_ADDRESS")
                    # TODO: add this instead of hardcoded 24 subnet, (add a flag for full scan option)
                    # subnet = i['prefixlen']

                    # unless specified explicitly with localhost scan flag, skip localhost ip addresses
                    if not self.event.localhost and ipaddress.startswith(InterfaceTypes.LOCALHOST.value):
                        continue

                    ip_network = IPNetwork(f"{ipaddress}/{sn}")
                    for ip in ip_network:
                        yield ip
        except Exception as x:
            logging.debug(f"Exception while generating subnet scan from local interfaces: {x}")
        finally:
            ip.release()

    def generate_interfaces_subnet_windows(self, sn="24"):
        from subprocess import check_output

        local_subnets = (
            check_output(
                "powershell -NoLogo -NoProfile -NonInteractive -ExecutionPolicy bypass -Command "
                ' "& {'
                "Get-NetIPConfiguration | Get-NetIPAddress | Where-Object {$_.AddressFamily -eq 'IPv4'}"
                " | Select-Object -Property IPAddress, PrefixLength | ConvertTo-Json "
                ' "}',
                shell=True,
            )
            .decode()
            .strip()
        )
        try:
            subnets = json.loads(local_subnets)
            for subnet in subnets:
                if not self.event.localhost and subnet["IPAddress"].startswith(InterfaceTypes.LOCALHOST.value):
                    continue
                ip_network = IPNetwork(f"{subnet['IPAddress']}/{sn}")
                for ip in ip_network:
                    yield ip

        except Exception as x:
            logging.debug(f"ERROR: Could not extract interface information using powershell - {x}")


# for comparing prefixes
class InterfaceTypes(Enum):
    LOCALHOST = "127"
