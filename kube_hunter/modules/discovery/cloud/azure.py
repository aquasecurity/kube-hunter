import logging
import requests

from kube_hunter.conf import get_config
from kube_hunter.core.types import Discovery
from kube_hunter.core.types.components import Azure
from kube_hunter.core.events.types import Vulnerability, Event, InstanceMetadataApiTechnique
from kube_hunter.core.events.event_handler import handler
from kube_hunter.modules.discovery.hosts import RunningAsPodEvent

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
        self.evidence = f"apiVersions: {','.join(self.versions_info.keys())}"


class AzureInstanceMetadataService:
    ROOT = "http://169.254.169.254/metadata/"
    VERSIONS_ENDPOINT = "versions/"
    INSTANCE_ENDPOINT = "instance/"

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


# def azure_metadata_discovery(self):
#     config = get_config()
#     logger.debug("From pod attempting to access azure's metadata")
#     machine_metadata = requests.get(
#         "http://169.254.169.254/metadata/instance?api-version=2017-08-01",
#         headers={"Metadata": "true"},
#         timeout=config.network_timeout,
#     ).json()
#     address, subnet = "", ""
#     subnets = list()
#     for interface in machine_metadata["network"]["interface"]:
#         address, subnet = (
#             interface["ipv4"]["subnet"][0]["address"],
#             interface["ipv4"]["subnet"][0]["prefix"],
#         )
#         subnet = subnet if not config.quick else "24"
#         logger.debug(f"From pod discovered subnet {address}/{subnet}")
#         subnets.append([address, subnet if not config.quick else "24"])
# -
#         self.publish_event(AzureMetadataApi(cidr=f"{address}/{subnet}"))
# -
#     return subnets, "Azure"
