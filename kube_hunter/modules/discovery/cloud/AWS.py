import enum
import logging
import requests
import ipaddress

from kube_hunter.conf import get_config
from kube_hunter.core.events import handler

from kube_hunter.core.types import Discovery, CloudProvider

from kube_hunter.core.events.types import Event, Vulnerability, NewHostEvent
from kube_hunter.core.types.vulnerabilities import InstanceMetadataApiTechnique

from kube_hunter.modules.discovery.hosts import RunningAsPodEvent

logger = logging.getLogger(__name__)

class EKSCluster(CloudProvider):
    """AWS Cluster"""

    name = "EKS Cluster"

class AWSMetadataApiExposed(Vulnerability, Event):
    """Access to the AWS Metadata API exposes information about the machines associated with the cluster"""    
    def __init__(self, version):
        Vulnerability.__init__(
            self,
            EKSCluster,
            "AWS Metadata Exposure",
            category=InstanceMetadataApiTechnique,
            vid="KHV053",
        )
        self.version = version 


class InstanceMetadataApi:
    URL = "http://169.254.169.254/latest/meta-data/"
    GET_MACS_URL = "http://169.254.169.254/latest/meta-data/mac" 
    LIST_CIDR_URL = "http://169.254.169.254/latest/meta-data/network/interfaces/macs/{mac_address}/subnet-ipv4-cidr-block"
    
    V2_REQUEST_TOKEN_URL = "http://169.254.169.254/latest/api/token/"
    V2_REQUEST_TOKEN_HEADER = {"X-aws-ec2-metatadata-token-ttl-seconds": "21600"}
    V2_TOKEN_HEADER_NAME = "X-aws-ec2-metatadata-token"
    
    @classmethod
    def get_api_token(cls, network_timeout):
        return requests.put(
                cls.V2_REQUEST_TOKEN_URL,
                headers=cls.V2_REQUEST_TOKEN_HEADER,
                timeout=network_timeout,
            ).text

    @classmethod
    def ping_v1(cls, network_timeout):
        status = requests.get(cls.URL, timeout=network_timeout).status_code
        return status == requests.codes.OK

    @classmethod
    def ping_v2(cls, token, network_timeout):
        status = requests.get(
                cls.URL,
                headers={cls.V2_TOKEN_HEADER_NAME: token},
                timeout=network_timeout,
            ).status_code
        return status == requests.codes.OK


@handler.subscribe(RunningAsPodEvent)
class AWSMetadataAPIDiscovery(Discovery):
    """AWS Metadata API Discovery
    Pings all metadata api versions and determines if they are accessible from the Pod
    """
    def __init__(self, event):
        self.event = event

    def execute(self):
        config = get_config()

        if self.check_metadata_v1(config.network_timeout):
            self.publish_event(AWSMetadataApiExposed(version="1"))
        
        if self.check_metadata_v2(config.network_timeout):
            self.publish_event(AWSMetadataApiExposed(version="2"))

    def check_metadata_v1(self, network_timeout):
        """Method checks if the metadata version v1 service is up and accessible from the pod"""
        try:
            logger.debug("From pod attempting to access AWS Metadata v1 API")
            return InstanceMetadataApi.ping_v1(network_timeout)
        except requests.exceptions.ConnectionError:
            logger.debug("Failed to connect to AWS metadata server v1")
        except Exception:
            logger.debug("Unknown error when trying to connect to AWS metadata v1 API")
        return False

    def check_metadata_v2(self, network_timeout):
        """Method checks if the metadata version v2 service is up and accessible from the pod"""
        try:
            logger.debug("From pod attempting to access AWS Metadata v2 API")
            token = InstanceMetadataApi.get_api_token()
            return InstanceMetadataApi.ping_v2(token, network_timeout)
        except requests.exceptions.ConnectionError:
            logger.debug("Failed to connect AWS metadata server v2")
        except Exception:
            logger.debug("Unknown error when trying to connect to AWS metadata v2 API")
        return False


@handler.subscribe(AWSMetadataApiExposed)
class AWSMetadataHostsDiscovery(Discovery):
    """AWS Metadata Hosts Discovery
    Scrapes the metadata api for additional accessible network subnets for kube-hunter to scan 
    """
    def __init__(self, event):
        self.event = event
    
    def execute(self):
        config = get_config()

        # Extracting network subnet from metadata api
        if self.event.version == "1":
            network = self.extract_network_subnet_v1(config.network_timeout)
        elif self.event.version == "2":
            network = self.extract_network_subnet_v2(config.network_timeout)

        # If quick scan is enabled we ignore the prefix and only use the network address
        if network:
            if config.quick:
                # TODO: change from hardcoded 24
                # Fallback to 24 default subnet
                network = ipaddress.IPv4Network(f"{network.network_address}/{24}")
        
        for ip in network:
            self.publish_event(NewHostEvent(host=ip))


    def extract_network_subnet_v1(self, network_timeout):
        """Extract network subnet from aws metadata api v1"""
        logger.debug("From pod attempting to access aws's metadata v1")

        mac_address = requests.get(InstanceMetadataApi.GET_MACS_URL, timeout=network_timeout).text
        logger.debug(f"Extracted mac from aws's metadata v1: {mac_address}")

        cidr_get_url = InstanceMetadataApi.LIST_CIDR_URL.format(mac_address=mac_address)
        cidr = requests.get(cidr_get_url, timeout=network_timeout).text
        logger.debug(f"Extracted cidr block from aws's metadata v1: {cidr}")

        try:
            network = ipaddress.IPv4Network(cidr.strip())
            return network
        except Exception as x:
            logger.debug(f"ERROR: could not parse cidr from aws metadata api: {cidr} - {x}")
        return None
    

    def extract_network_subnet_v2(self, network_timeout):
        """Extract network subnet from aws metadata api v1"""
        logger.debug("From pod attempting to access aws's metadata v2")
        
        token = InstanceMetadataApi.get_api_token()

        mac_address = requests.get(
            InstanceMetadataApi.GET_MACS_URL,
            headers={InstanceMetadataApi.V2_TOKEN_HEADER_NAME: token},
            timeout=network_timeout,
        ).text

        cidr_get_url = InstanceMetadataApi.LIST_CIDR_URL.format(mac_address=mac_address)
        cidr = requests.get(
            cidr_get_url,
            headers={InstanceMetadataApi.V2_TOKEN_HEADER_NAME: token},
            timeout=network_timeout,
        ).text.split("/")

        try:
            network = ipaddress.IPv4Network(cidr.strip())
            return network
        except Exception as x:
            logger.debug(f"ERROR: could not parse cidr from aws metadata api: {cidr} - {x}")
        return None
    