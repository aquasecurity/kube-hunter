import os
import logging
import requests

from enum import Enum
from netaddr import IPNetwork, IPAddress
from netifaces import AF_INET, ifaddresses, interfaces

from kube_hunter.conf import config
from kube_hunter.core.events import handler
from kube_hunter.core.events.types import Event, NewHostEvent, Vulnerability
from kube_hunter.core.types import Discovery, InformationDisclosure, Azure

logger = logging.getLogger(__name__)


class RunningAsPodEvent(Event):
    def __init__(self):
        self.name = 'Running from within a pod'
        self.auth_token = self.get_service_account_file("token")
        self.client_cert = self.get_service_account_file("ca.crt")
        self.namespace = self.get_service_account_file("namespace")
        self.kubeservicehost = os.environ.get("KUBERNETES_SERVICE_HOST", None)

    # Event's logical location to be used mainly for reports.
    def location(self):
        location = "Local to Pod"
        if 'HOSTNAME' in os.environ:
            location += "(" + os.environ['HOSTNAME'] + ")"

        return location

    def get_service_account_file(self, file):
        try:
            with open(f"/var/run/secrets/kubernetes.io/serviceaccount/{file}") as f:
                return f.read()
        except IOError:
            pass


class AzureMetadataApi(Vulnerability, Event):
    """Access to the Azure Metadata API exposes information about the machines associated with the cluster"""
    def __init__(self, cidr):
        Vulnerability.__init__(self, Azure, "Azure Metadata Exposure", category=InformationDisclosure, vid="KHV003")
        self.cidr = cidr
        self.evidence = "cidr: {}".format(cidr)


class HostScanEvent(Event):
    def __init__(self, pod=False, active=False, predefined_hosts=list()):
        # flag to specify whether to get actual data from vulnerabilities
        self.active = active
        self.predefined_hosts = predefined_hosts


class HostDiscoveryHelpers:
    # generator, generating a subnet by given a cidr
    @staticmethod
    def generate_subnet(ip, sn="24", ignore=None):
        logger.debug(f"HostDiscoveryHelpers.generate_subnet {ip}/{sn}")
        subnet = f"{ip}/{sn}"
        for ip in IPNetwork(subnet):
            if ignore and any(ip in s for s in ignore):
                logger.debug(f"HostDiscoveryHelpers.generate_subnet DENIED {ip}")
            else:
                logger.debug(f"HostDiscoveryHelpers.generate_subnet yielding {ip}")
                yield ip

    @staticmethod
    def gen_ips():
        ignore = list()
        scan = list()
        for cidr in config.cidr:
            try:
                ip, sn = cidr.split('/')
            except ValueError:
                logger.exception(f"Unable to parse CIDR \"{config.cidr}\"")
                break
            if ip.startswith('!'):
                ignore.append(IPNetwork(f"{ip[1:]}/{sn}"))
            else:
                scan.append([ip, sn])

        for ip, sn in scan:
            yield from HostDiscoveryHelpers.generate_subnet(ip=ip, sn=sn, ignore=ignore)


@handler.subscribe(RunningAsPodEvent)
class FromPodHostDiscovery(Discovery):
    """Host Discovery when running as pod
    Generates ip adresses to scan, based on cluster/scan type
    """
    def __init__(self, event):
        self.event = event

    def execute(self):
        # Scan any hosts that the user specified
        if config.remote or config.cidr:
            self.publish_event(HostScanEvent())
        else:
            # Discover cluster subnets, we'll scan all these hosts
            cloud = None
            if self.is_azure_pod():
                subnets, cloud = self.azure_metadata_discovery()
            else:
                subnets, ext_ip = self.traceroute_discovery()

            should_scan_apiserver = False
            if self.event.kubeservicehost:
                should_scan_apiserver = True
            for subnet in subnets:
                if self.event.kubeservicehost and self.event.kubeservicehost in IPNetwork(f"{subnet[0]}/{subnet[1]}"):
                    should_scan_apiserver = False
                logger.debug(f"From pod scanning subnet {subnet[0]}/{subnet[1]}")
                for ip in HostDiscoveryHelpers.generate_subnet(ip=subnet[0], sn=subnet[1]):
                    self.publish_event(NewHostEvent(host=ip, cloud=cloud))
            if should_scan_apiserver:
                self.publish_event(NewHostEvent(host=IPAddress(self.event.kubeservicehost), cloud=cloud))

    def is_azure_pod(self):
        try:
            logger.debug("From pod attempting to access Azure Metadata API")
            if requests.get("http://169.254.169.254/metadata/instance?api-version=2017-08-01",
                            headers={"Metadata": "true"},
                            timeout=config.network_timeout).status_code == 200:
                return True
        except requests.exceptions.ConnectionError:
            logger.debug("Failed to connect Azure metadata server")
            return False

    # for pod scanning
    def traceroute_discovery(self):
        # getting external ip, to determine if cloud cluster
        external_ip = requests.get("https://canhazip.com", timeout=config.network_timeout).text
        from scapy.all import ICMP, IP, Ether, srp1

        node_internal_ip = srp1(
            Ether()/IP(dst="1.1.1.1", ttl=1)/ICMP(),
            verbose=0,
            timeout=config.network_timeout)[IP].src
        return [[node_internal_ip, "24"]], external_ip

    # querying azure's interface metadata api | works only from a pod
    def azure_metadata_discovery(self):
        logger.debug("From pod attempting to access azure's metadata")
        machine_metadata = requests.get(
            "http://169.254.169.254/metadata/instance?api-version=2017-08-01",
            headers={"Metadata": "true"},
            timeout=config.network_timeout).json()
        address, subnet = "", ""
        subnets = list()
        for interface in machine_metadata["network"]["interface"]:
            address, subnet = interface["ipv4"]["subnet"][0]["address"], interface["ipv4"]["subnet"][0]["prefix"]
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
        if config.cidr:
            for ip in HostDiscoveryHelpers.gen_ips():
                self.publish_event(NewHostEvent(host=ip))
        elif config.interface:
            self.scan_interfaces()
        elif len(config.remote) > 0:
            for host in config.remote:
                self.publish_event(NewHostEvent(host=host))

    # for normal scanning
    def scan_interfaces(self):
        try:
            logger.debug("HostDiscovery hunter attempting to get external IP address")
            # getting external ip, to determine if cloud cluster
            external_ip = requests.get("https://canhazip.com", timeout=config.network_timeout).text
        except requests.ConnectionError:
            logger.warning(f"Unable to determine external IP address, using 127.0.0.1", exc_info=True)
            external_ip = "127.0.0.1"
        for ip in self.generate_interfaces_subnet():
            handler.publish_event(NewHostEvent(host=ip))

    # generate all subnets from all internal network interfaces
    def generate_interfaces_subnet(self, sn='24'):
        for ifaceName in interfaces():
            for ip in [i['addr'] for i in ifaddresses(ifaceName).setdefault(AF_INET, [])]:
                if not self.event.localhost and InterfaceTypes.LOCALHOST.value in ip.__str__():
                    continue
                for ip in HostDiscoveryHelpers.generate_subnet(ip, sn):
                    yield ip


# for comparing prefixes
class InterfaceTypes(Enum):
    LOCALHOST = "127"
