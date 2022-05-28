import logging
import requests

from kube_hunter.conf import get_config
from kube_hunter.core.types import Discovery
from kube_hunter.core.types.components import Azure
from kube_hunter.core.events.types import Vulnerability, Event, InstanceMetadataApiTechnique
from kube_hunter.core.events.event_handler import handler
from kube_hunter.modules.discovery.hosts import RunningAsPodEvent, NewHostEvent

from ipaddress import IPv4Network

logger = logging.getLogger(__name__)


class AzureMetadataApiExposed(Vulnerability, Event):
    """Access to the Azure Metadata API exposes information about the machines associated with the cluster"""

    def __init__(self, versions_info):
        Vulnerability.__init__(
            self,
            Azure,
            "Azure Metadata Exposure",
            category=InstanceMetadataApiTechnique,
            vid="KHV003",
        )

        # dict containing all api versions instance api extracted
        self.versions_info = versions_info
        self.evidence = f"apiVersions: {','.join(self.versions_info['apiVersions'].keys())}"


class AzureInstanceMetadataService:
    ROOT = "http://169.254.169.254/metadata/"
    VERSIONS_ENDPOINT = "versions"
    INSTANCE_ENDPOINT = "instance"

    VERSION_PARAMETER = "api-version"
    REQUEST_TOKEN_HEADER = {"Metadata": "true"}

    @classmethod
    def get_versions(cls, network_timeout):
        try:
            return requests.get(
                cls.ROOT + cls.VERSIONS_ENDPOINT,
                headers=cls.REQUEST_TOKEN_HEADER,
                timeout=network_timeout,
            ).json()
        except requests.exceptions.ConnectionError:
            logger.debug("Failed to connect Azure metadata server")
        except Exception:
            logger.debug("Unknown error when trying to connect to Azure metadata server")
        return False

    @classmethod
    def get_instance_data(cls, api_version, network_timeout):
        try:
            return requests.get(
                cls.ROOT + cls.INSTANCE_ENDPOINT,
                params={cls.VERSION_PARAMETER: api_version},
                headers=cls.REQUEST_TOKEN_HEADER,
                timeout=network_timeout,
            ).json()
        except requests.exceptions.ConnectionError:
            logger.debug("Failed to connect Azure metadata server")
        except Exception:
            logger.debug("Unknown error when trying to connect to Azure metadata server")
        return False


@handler.subscribe(RunningAsPodEvent)
class AzureInstanceMetadataServiceDiscovery(Discovery):
    def __init__(self, event):
        self.event = event

    def execute(self):
        config = get_config()

        logger.debug("Trying to access IMDS (Azure Metadata Service) from pod")
        available_versions = AzureInstanceMetadataService.get_versions(network_timeout=config.network_timeout)

        if not available_versions:
            logger.debug("IMDS not available")
            return

        versions_info = dict()
        for version in available_versions:
            instance_data = AzureInstanceMetadataService.get_instance_data(
                api_version=version, network_timeout=config.network_timeout
            )
            if instance_data:
                logger.debug(f"Successfully extracted IMDS apiVersion {version} instance data")
                versions_info[version] = instance_data

        self.publish_event(AzureMetadataApiExposed(versions_info=versions_info))


@handler.subscribe(AzureMetadataApiExposed)
class AzureSubnetsDiscovery(Discovery):
    def __init__(self, event):
        self.event = event

    def extract_azure_subnet(self):
        # default to 24 subnet
        address, prefix = None, "24"
        config = get_config()
        # import ipdb; ipdb.set_trace()
        for version, info in self.event.versions_info.items():
            try:
                address = info["network"]["interface"][0]["ipv4"]["subnet"][0]["address"]
                tmp_prefix = info["network"]["interface"][0]["ipv4"]["subnet"][0]["prefix"]

                if config.quick:
                    logger.debug(f"Discovered azure subnet {tmp_prefix} but scanning {prefix} due to `quick` option ")
                else:
                    prefix = tmp_prefix

                return f"{address}/{prefix}"
            except Exception as x:
                logger.debug(f"Skipping azure subnet discovery for version {version}: {x}")
                continue
        return False

    def execute(self):
        subnet = self.extract_azure_subnet()
        if subnet:
            logger.debug(f"From pod discovered azure subnet {subnet}")
            for ip in IPv4Network(f"{subnet}"):
                self.publish_event(NewHostEvent(str(ip)))
