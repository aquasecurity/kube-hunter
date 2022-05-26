import os
import logging
import itertools

from enum import Enum
from netaddr import IPNetwork, IPAddress, AddrFormatError
from netifaces import AF_INET, ifaddresses, interfaces, gateways

from kube_hunter.conf import get_config
from kube_hunter.modules.discovery.kubernetes_client import list_all_k8s_cluster_nodes
from kube_hunter.core.types import Discovery
from kube_hunter.core.events.event_handler import handler
from kube_hunter.core.events.types import Event, NewHostEvent

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
            subnets = self.gateway_discovery()

            should_scan_apiserver = False
            if self.event.kubeservicehost:
                should_scan_apiserver = True
            for ip, mask in subnets:
                if self.event.kubeservicehost and self.event.kubeservicehost in IPNetwork(f"{ip}/{mask}"):
                    should_scan_apiserver = False
                logger.debug(f"From pod scanning subnet {ip}/{mask}")
                for ip in IPNetwork(f"{ip}/{mask}"):
                    self.publish_event(NewHostEvent(host=ip))
            if should_scan_apiserver:
                self.publish_event(NewHostEvent(host=self.event.kubeservicehost))

    # for pod scanning
    def gateway_discovery(self):
        """Retrieving default gateway of pod, which is usually also a contact point with the host"""
        return [[gateways()["default"][AF_INET][0], "24"]]


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
        for ifaceName in interfaces():
            for ip in [i["addr"] for i in ifaddresses(ifaceName).setdefault(AF_INET, [])]:
                if not self.event.localhost and InterfaceTypes.LOCALHOST.value in ip.__str__():
                    continue
                for ip in IPNetwork(f"{ip}/{sn}"):
                    yield ip


# for comparing prefixes
class InterfaceTypes(Enum):
    LOCALHOST = "127"
