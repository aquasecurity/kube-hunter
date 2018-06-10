import logging
from enum import Enum

from requests import get

from ..discovery.dashboard import KubeDashboardEvent
from ..discovery.proxy import KubeProxyEvent
from ..events import handler
from ..events.types import Vulnerability, Event, KubernetesCluster
from ..types import Hunter


class Service(Enum):
    DASHBOARD = "kubernetes-dashboard"

class KubeProxyExposed(Vulnerability, Event):
    """Exposes all oprations on the cluster"""
    def __init__(self):
        Vulnerability.__init__(self, KubernetesCluster, "Proxy Exposed")

@handler.subscribe(KubeProxyEvent)
class KubeProxy(Hunter):
    def __init__(self, event):
        self.event = event
        self.api_url = "http://{host}:{port}/api/v1".format(host=self.event.host, port=self.event.port)

    def execute(self):
        self.publish_event(KubeProxyExposed())
        for namespace, services in self.services.items():
            for service in services:
                if service == Service.DASHBOARD.value:
                    logging.debug(service)
                    curr_path = "api/v1/namespaces/{ns}/services/{sv}/proxy".format(ns=namespace,sv=service) # TODO: check if /proxy is a convention on other services
                    self.publish_event(KubeDashboardEvent(path=curr_path, secure=False))

    @property
    def namespaces(self):
        resource_json = get(self.api_url + "/namespaces").json()
        return self.extract_names(resource_json)

    @property
    def services(self):
        # map between namespaces and service names
        services = dict()
        for namespace in self.namespaces:
            resource_path = "/namespaces/{ns}/services".format(ns=namespace)
            resource_json = get(self.api_url + resource_path).json()
            services[namespace] = self.extract_names(resource_json)
        logging.debug(services)
        return services

    @staticmethod
    def extract_names(resource_json):
        names = list()
        for item in resource_json["items"]:
            names.append(item["metadata"]["name"])
        return names
