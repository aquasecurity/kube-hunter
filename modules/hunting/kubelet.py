import json
import logging
from ..types import Hunter

import requests
import urllib3

from ..events import handler
from ..events.types import ReadOnlyKubeletEvent, SecureKubeletEvent, KubeletVulnerability

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

""" dividing ports for seperate hunters """
@handler.subscribe(ReadOnlyKubeletEvent)
class ReadOnlyKubeletPortHunter(Hunter):
    def __init__(self, event):
        self.event = event

    def execute(self):
        pass
        
@handler.subscribe(SecureKubeletEvent)        
class SecurePortKubeletHunter(Hunter):
    def __init__(self, event):
        self.event = event

    def execute(self):
        self.check_debug_handlers()

    def check_debug_handlers(self):
        pod, container = self.get_kubesystem_pod_container()       
        if self.exec_handler(pod, container):
            self.publish_event(KubeletVulnerability(desc="exec enabled"))

    def get_kubesystem_pod_container(self):
        pods_data = json.loads(requests.get("https://{host}:{port}/pods".format(host=self.event.host, port=self.event.port), verify=False).text)['items']
        # filter running kubesystem pod
        kubesystem_pod = lambda pod: pod["metadata"]["namespace"] == "kube-system" and pod["status"]["phase"] == "Running"        
        pod_data = (pod_data for pod_data in pods_data if kubesystem_pod(pod_data)).next()

        container_data = (container_data for container_data in pod_data["spec"]["containers"]).next()
        return pod_data["metadata"]["name"], container_data["name"]

    # returns true if successfull
    def exec_handler(self, pod, container):
        headers = {
            "X-Stream-Protocol-Version": "v2.channel.k8s.io",
        }
        exec_url = "https://{host}:10250/exec/{pod_ns}/{pod}/{cont_name}?command={cmd}&input=1&output=1&tty=1".format(
            host = self.event.host,
            pod_ns = "kube-system",
            pod = pod,
            cont_name = container,
            cmd = "uname"
        )
        stream = requests.post(url=exec_url, headers=headers, verify=False, allow_redirects=False).headers.get("location", default=None)
        return bool(stream)
