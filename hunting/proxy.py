import events
from requests import get
from enum import Enum

class Service(Enum):
    DASHBOARD = "kubernetes-dashboard"

class KubeProxy(object):
    def __init__(self, task):
        self.host = task['host']
        self.port = task['port'] or 8001

        self.api_url = "http://{host}:{port}/api/v1".format(host=self.host, port=self.port)

    def execute(self):
        for namespace, services in self.services.items():
            for service in services:
                curr_path = "api/v1/namespaces/{ns}/services/{sv}/proxy".format(ns=namespace,sv=service) # TODO: check if /proxy is a convention on other services
                if service == Service.DASHBOARD.value:
                    events.handler.publish_event('KUBE_DASHBOARD', {"host": self.host, "port": self.port, "location": curr_path, 'secure': False})

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
        return services

    @staticmethod
    def extract_names(resource_json):
        names = list()
        for item in resource_json["items"]:
            names.append(item["metadata"]["name"])
        return names

events.handler.subscribe_event('KUBE_PROXY', KubeProxy)