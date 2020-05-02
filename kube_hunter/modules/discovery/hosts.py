import os
import logging
import itertools
import requests

from typing import Iterable, Iterator, Optional
from netaddr import IPNetwork, IPAddress, AddrFormatError
from netifaces import AF_INET, ifaddresses, interfaces
from scapy.all import ICMP, IP, Ether, srp1
from kube_hunter.conf import get_config
from kube_hunter.core.events import NewHostEvent
from kube_hunter.core.pubsub.subscription import Event, subscribe
from kube_hunter.core.types import AKSCluster, Discovery, InformationDisclosure, Vulnerability

logger = logging.getLogger(__name__)


class RunningAsPodEvent(Event):
    def __init__(self):
        self.name = "Running from within a pod"
        self.auth_token = self.get_service_account_file("token")
        self.client_cert = self.get_service_account_file("ca.crt")
        self.namespace = self.get_service_account_file("namespace")
        self.kubeservicehost = os.getenv("KUBERNETES_SERVICE_HOST")

    def location(self):
        location = "Local to pod"
        hostname = os.getenv("HOSTNAME")
        if hostname:
            location += f" ({hostname})"
        return location

    def get_service_account_file(self, file):
        try:
            with open(f"/var/run/secrets/kubernetes.io/serviceaccount/{file}") as f:
                return f.read()
        except IOError:
            pass


class AzureMetadataApi(Vulnerability):
    """Access to the Azure Metadata API exposes information about the machines associated with the cluster"""

    cidr: str

    def __init__(self, cidr: str):
        super().__init__(
            name="Azure Metadata Exposure",
            component=AKSCluster,
            category=InformationDisclosure,
            vid="KHV003",
            evidence=f"cidr: {cidr}",
        )
        self.cidr = cidr


class HostScanEvent(Event):
    def __init__(self, active=False, predefined_hosts=None):
        # flag to specify whether to get actual data from vulnerabilities
        self.active = active
        self.predefined_hosts = predefined_hosts or []


class HostDiscoveryHelpers:
    # generator, generating a subnet by given a cidr
    @staticmethod
    def filter_subnet(subnet: IPNetwork, ignore: Optional[Iterable[IPAddress]] = None) -> Iterator[IPAddress]:
        for ip in subnet:
            if ignore and any(ip in s for s in ignore):
                logger.debug(f"HostDiscoveryHelpers.filter_subnet ignoring {ip}")
            else:
                yield ip

    @staticmethod
    def generate_hosts(cidrs: Iterable[str]) -> Iterator[IPAddress]:
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


@subscribe(RunningAsPodEvent)
class FromPodHostDiscovery(Discovery):
    """Host Discovery when running as pod
    Generates ip adresses to scan, based on cluster/scan type
    """

    def execute(self):
        config = get_config()
        # Scan any hosts that the user specified
        if config.remote or config.cidr:
            yield HostScanEvent()
        else:
            # Discover cluster subnets, we'll scan all these hosts
            cloud = None
            if self.is_azure_pod():
                subnets, cloud = self.azure_metadata_discovery()
                for address, mask in subnets:
                    yield AzureMetadataApi(cidr=f"{address}/{mask}")
            else:
                subnets = self.traceroute_discovery()

            should_scan_apiserver = False
            if self.event.kubeservicehost:
                should_scan_apiserver = True
            for subnet in subnets:
                if self.event.kubeservicehost and self.event.kubeservicehost in subnet:
                    should_scan_apiserver = False
                logger.debug(f"From pod scanning subnet {subnet}")
                for ip in subnet:
                    yield NewHostEvent(host=ip, cloud=cloud)
            if should_scan_apiserver:
                yield NewHostEvent(host=IPAddress(self.event.kubeservicehost), cloud=cloud)

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
            return False

    # for pod scanning
    def traceroute_discovery(self) -> Iterable[IPNetwork]:
        config = get_config()
        node_internal_ip = srp1(
            Ether() / IP(dst="1.1.1.1", ttl=1) / ICMP(), verbose=0, timeout=config.network_timeout,
        )[IP].src
        return [IPNetwork(f"{node_internal_ip}/24")]

    # querying azure's interface metadata api | works only from a pod
    def azure_metadata_discovery(self) -> Iterable[IPNetwork]:
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
            subnets.append([IPNetwork(f"{address}/{subnet}")])

        return subnets, "Azure"


@subscribe(HostScanEvent)
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
                yield NewHostEvent(host=ip)
        elif config.interface:
            for ip in self.generate_interfaces_subnet():
                yield NewHostEvent(host=ip)
        elif config.remote:
            for host in config.remote:
                yield NewHostEvent(host=host)

    def generate_interfaces_subnet(self, sn="24"):
        for ifaceName in interfaces():
            for ip in [i["addr"] for i in ifaddresses(ifaceName).setdefault(AF_INET, [])]:
                if not self.event.localhost and str(ip).startswith("127"):
                    continue
                yield from IPNetwork(f"{ip}/{sn}")
