import logging
from enum import Enum

import requests
import json

from ...core.util import get_client_cert
from ...core.events import handler
from ...core.events.types import Event, Vulnerability
from ...core.types import ActiveHunter, Hunter, KubernetesCluster, InformationDisclosure
from ..discovery.dashboard import KubeDashboardEvent
from ..discovery.proxy import KubeProxyEvent

""" Vulnerabilities """
class KubeProxyExposed(Vulnerability, Event):
    """All oprations on the cluster are exposed"""
    def __init__(self):
        Vulnerability.__init__(self, KubernetesCluster, "Proxy Exposed", category=InformationDisclosure)

class K8sVersionDisclosure(Vulnerability, Event):
    """The Kubernetes version is exposed from kube-proxy"""
    def __init__(self):
        Vulnerability.__init__(self, KubernetesCluster, "K8s Version Disclosure", category=InformationDisclosure)


class Service(Enum):
    DASHBOARD = "kubernetes-dashboard"

@handler.subscribe(KubeProxyEvent)
class KubeProxy(Hunter):
    """Proxy Hunting
    Hunts for a dashboard behind the proxy 
    """
    def __init__(self, event):
        self.event = event
        self.api_url = "http://{host}:{port}/api/v1".format(host=self.event.host, port=self.event.port)

    def execute(self):
        self.publish_event(KubeProxyExposed())
        self.publish_event(K8sVersionDisclosure())
        for namespace, services in self.services.items():
            for service in services:
                if service == Service.DASHBOARD.value:
                    logging.debug(service)
                    curr_path = "api/v1/namespaces/{ns}/services/{sv}/proxy".format(ns=namespace,sv=service) # TODO: check if /proxy is a convention on other services
                    self.publish_event(KubeDashboardEvent(path=curr_path, secure=False))

    @property
    def namespaces(self):
        resource_json = requests.get(self.api_url + "/namespaces", cert=get_client_cert()).json()
        return self.extract_names(resource_json)

    @property
    def services(self):
        # map between namespaces and service names
        services = dict()
        for namespace in self.namespaces:
            resource_path = "/namespaces/{ns}/services".format(ns=namespace)
            resource_json = requests.get(self.api_url + resource_path, cert=get_client_cert()).json()
            services[namespace] = self.extract_names(resource_json)
        logging.debug(services)
        return services

    @staticmethod
    def extract_names(resource_json):
        names = list()
        for item in resource_json["items"]:
            names.append(item["metadata"]["name"])
        return names

@handler.subscribe(KubeProxyExposed)
class ProveProxyExposed(ActiveHunter):
    """Build Date Hunter
    Hunts when proxy is exposed, extracts the build date of kubernetes
    """
    def __init__(self, event):
        self.event = event

    def execute(self):
        version_metadata = json.loads(requests.get("http://{host}:{port}/version".format(
            host=self.event.host,
            port=self.event.port,
        ), verify=False, cert=get_client_cert()).text)
        if "buildDate" in version_metadata:
            self.event.evidence = "build date: {}".format(version_metadata["buildDate"])

@handler.subscribe(K8sVersionDisclosure)
class ProveK8sVersionDisclosure(ActiveHunter):
    """K8s Version Hunter
    Hunts Proxy when exposed, extracts the version
    """
    def __init__(self, event):
        self.event = event

    def execute(self):
        version_metadata = json.loads(requests.get("http://{host}:{port}/version".format(
            host=self.event.host,
            port=self.event.port,
        ), verify=False, cert=get_client_cert()).text)
        if "gitVersion" in version_metadata:
            self.event.evidence = "version: {}".format(version_metadata["gitVersion"])
