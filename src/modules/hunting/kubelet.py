import json
import logging
from enum import Enum

import requests
import urllib3

from __main__ import config
from ...core.events import handler
from ...core.events.types import (KubernetesCluster, Kubelet, Vulnerability, Information, Event)
from ..discovery.kubelet import KubeletExposedHandler, ReadOnlyKubeletEvent, SecureKubeletEvent
from ...core.types import Hunter, ActiveHunter
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ContainerLogsHandler:
    """Outputs logs from a running container"""
    name="/containerLogs"
    remediation="--enable-debugging-handlers=False On Kubelet"

class RunningPodsHandler:
    """Outputs a list of currently runnning pods, and some of their metadata"""
    name="/runningpods"
    remediation="--enable-debugging-handlers=False On Kubelet"    

class ExecHandler:
    """Opens a websocket that enables running and executing arbitrary commands on a container"""
    name="/exec"
    remediation="--enable-debugging-handlers=False On Kubelet"    

class RunHandler:
    """Allows remote arbitrary execution inside a container"""
    name="/run"
    remediation="--enable-debugging-handlers=False On Kubelet"    

class PortForwardHandler:
    """Setting a port forwaring rule on a pod"""
    name="/portForward"
    remediation="--enable-debugging-handlers=False On Kubelet"

class AttachHandler:
    """Opens a websocket that enables running and executing arbitrary commands on a container"""
    name="/attach"
    remediation="--enable-debugging-handlers=False On Kubelet"
        

""" Vulnerabilities """
class K8sVersionDisclosure(Vulnerability, Event):
    """Discloses the kubernetes version, exposed from a log on the /metrics endpoint"""
    def __init__(self, version):
        Vulnerability.__init__(self, Kubelet, "Version Disclosure")
        self.version = version
    
    def proof(self):
        return self.version

class PrivilegedContainers(Vulnerability, Event):
    """A priviledged container on a node, can expose the node/cluster to unwanted root operations"""
    def __init__(self, containers):
        Vulnerability.__init__(self, KubernetesCluster, "Priviledged Container")
        self.containers = containers
        
    def proof(self):
        return self.containers


""" dividing ports for seperate hunters """
@handler.subscribe(ReadOnlyKubeletEvent)
class ReadOnlyKubeletPortHunter(Hunter):
    def __init__(self, event):
        self.event = event
        self.path = "http://{}:{}/".format(self.event.host, self.event.port)

    def get_k8s_version(self):
        metrics = requests.get(self.path + "metrics").text
        for line in metrics.split("\n"):
            if line.startswith("kubernetes_build_info"):
                for info in line[line.find('{') + 1: line.find('}')].split(','):
                    k, v = info.split("=")
                    if k == "gitVersion":
                        return v.strip("\"")
    
    # returns list of tuples of priviledged container and their pod. 
    def find_privileged_containers(self):
        pods = json.loads(requests.get(self.path + "pods").text)
        privileged_containers = list()
        if "items" in pods:
            for pod in pods["items"]:
                for container in pod["spec"]["containers"]:
                    if "securityContext" in container and "privileged" in container["securityContext"] and container["securityContext"]["privileged"]:
                        privileged_containers.append((pod["metadata"]["name"], container["name"]))
        return privileged_containers if len(privileged_containers) > 0 else None

    def execute(self):
        k8s_version = self.get_k8s_version()
        privileged_containers = self.find_privileged_containers()
        if k8s_version:
            self.publish_event(K8sVersionDisclosure(version=k8s_version))
        if privileged_containers:
            self.publish_event(PrivilegedContainers(containers=privileged_containers))
        
@handler.subscribe(SecureKubeletEvent)        
class SecureKubeletPortHunter(Hunter):
    class DebugHandlers(object):    
        """ all methods will return the handler name if successfull """
        class Handlers(Enum):
            CONTAINERLOGS = "containerLogs/{podNamespace}/{podID}/{containerName}"                        # GET
            RUNNINGPODS = "runningpods"                                                                   # GET
            EXEC = "exec/{podNamespace}/{podID}/{containerName}?command={cmd}&input=1&output=1&tty=1"     # GET -> WebSocket 
            RUN = "run/{podNamespace}/{podID}/{containerName}?cmd={cmd}"                                  # POST, For legacy reasons, it uses different query param than exec.
            PORTFORWARD = "portForward/{podNamespace}/{podID}?port={port}"                                # GET/POST
            ATTACH = "attach/{podNamespace}/{podID}/{containerName}?command={cmd}&input=1&output=1&tty=1" # GET -> WebSocket

        class PodData(object):
            def __init__(self, **kargs):
                self.__dict__.update(**kargs)
            def __str__(self):
                return str(self.__dict__)

        def __init__(self, path, session=None, **kargs):
            self.path = path
            self.session = session if session else requests.Session()
            self.pod = self.PodData(**kargs)
            
        # outputs logs from a specific container
        def test_container_logs(self):
            logs_url = self.path + self.Handlers.CONTAINERLOGS.value.format(
                podNamespace=self.pod.namespace,
                podID=self.pod.name,
                containerName=self.pod.container
            )
            if self.session.get(logs_url, verify=False).status_code == 200:
                return ContainerLogsHandler
        
        # need further investigation on websockets protocol for further implementation
        def test_exec_container(self):
            # opens a stream to connect to using a web socket
            headers={"X-Stream-Protocol-Version": "v2.channel.k8s.io"}
            exec_url = self.path + self.Handlers.EXEC.value.format(
                podNamespace = self.pod.namespace,
                podID = self.pod.name,
                containerName = self.pod.container,
                cmd = "uname -a"
            )
            if "/cri/exec/" in self.session.get(exec_url, headers=headers, allow_redirects=False ,verify=False).text:
                return ExecHandler

        # need further investigation on websockets protocol for further implementation
        def test_port_forward(self):
            headers = {
                "Upgrade": "websocket",  
                "Connection": "Upgrade",
                "Sec-Websocket-Key": "s",
                "Sec-Websocket-Version": "13",
                "Sec-Websocket-Protocol": "SPDY"

            }
            pf_url = self.path + self.Handlers.PORTFORWARD.value.format(
                podNamespace=self.pod.namespace,
                podID=self.pod.name,
                port=80
            )
            self.session.get(pf_url, headers=headers, verify=False, stream=True).status_code == 200
            #TODO: what to return?

        # executes one command and returns output
        def test_run_container(self):
            run_url = self.path + self.Handlers.RUN.value.format(
                podNamespace = self.pod.namespace,
                podID = self.pod.name,
                containerName = self.pod.container,
                cmd = "uname -a"
            )
            output = requests.post(run_url, allow_redirects=False ,verify=False).text        
            if "echo" not in output and "check" in output:
                return RunHandler 

        # returns list of currently running pods
        def test_running_pods(self):
            pods_url = self.path + self.Handlers.RUNNINGPODS.value
            if 'items' in json.loads(self.session.get(pods_url, verify=False).text).keys():
                return RunningPodsHandler
        
        # need further investigation on the differences between attach and exec
        def test_attach_container(self):
            # headers={"X-Stream-Protocol-Version": "v2.channel.k8s.io"}
            attach_url = self.path + self.Handlers.ATTACH.value.format(
                podNamespace = self.pod.namespace,
                podID = self.pod.name,
                containerName = self.pod.container,
                cmd = "uname -a"
            )
            if "/cri/attach/" in self.session.get(attach_url, allow_redirects=False ,verify=False).text:
                return AttachHandler

    def __init__(self, event):
        self.event = event
        self.session = requests.Session()
        if self.event.secure:
            self.session.headers.update({"Authorization": "Bearer {}".format(self.event.auth_token)})
            self.session.cert = self.event.client_cert
        self.path = "https://{}:{}/".format(self.event.host, 10250)

    def execute(self):
        self.test_debugging_handlers()

    def test_debugging_handlers(self):
        # if kube-hunter runs in a pod, we test with kube-hunter's pod        
        pod = self.get_self_pod() if config.pod else self.get_random_pod()
        debug_handlers = self.DebugHandlers(self.path, **pod)
        test_list = [
            debug_handlers.test_container_logs, 
            debug_handlers.test_exec_container,
            debug_handlers.test_run_container,
            debug_handlers.test_running_pods,
            debug_handlers.test_port_forward,
            debug_handlers.test_attach_container
        ]
        for test_handler in test_list:
            try:
                handler = test_handler()
                if handler:
                    self.publish_event(KubeletExposedHandler(handler=handler))
            except Exception as ex:
                logging.debug("Failed getting handler: {}".format(test_handler))
                pass
            
    def get_self_pod(self):
        return {"name": "kube-hunter", 
                "namespace": "default", 
                "container": "kube-hunter"}

    # trying to get a pod from default namespace, if doesnt exist, gets a kube-system one
    def get_random_pod(self):
        pods_data = json.loads(self.session.get("https://{host}:{port}/pods".format(host=self.event.host, port=self.event.port), verify=False).text)['items']
        # filter running kubesystem pod
        is_default_pod = lambda pod: pod["metadata"]["namespace"] == "default" and pod["status"]["phase"] == "Running"        
        is_kubesystem_pod = lambda pod: pod["metadata"]["namespace"] == "kube-system" and pod["status"]["phase"] == "Running"
        pod_data = next((pod_data for pod_data in pods_data if is_default_pod(pod_data)), None)
        if not pod_data:
            pod_data = next((pod_data for pod_data in pods_data if is_kubesystem_pod(pod_data)), None)
        
        container_data = (container_data for container_data in pod_data["spec"]["containers"]).next()
        return {
            "name": pod_data["metadata"]["name"],
            "container": container_data["name"],
            "namespace": "default"
        }


""" Active Hunting Of Handlers"""
@handler.subscribe(KubeletExposedHandler, predicate=lambda x: x.handler.name==ExecHandler.name)
class ActiveExecHandler(ActiveHunter):
    def __init__(self, event):
        self.event = event

    def execute(self):
        pass
        
@handler.subscribe(KubeletExposedHandler, predicate=lambda x: x.handler.name==RunHandler.name)
class ActiveRunHandler(ActiveHunter):
    def __init__(self, event):
        self.event = event

    def execute(self):
        pass

@handler.subscribe(KubeletExposedHandler, predicate=lambda x: x.handler.name==ContainerLogsHandler.name)
class ActiveContainerLogs(ActiveHunter):
    def __init__(self, event):
        self.event = event

    def execute(self):
        pass

@handler.subscribe(KubeletExposedHandler, predicate=lambda x: x.handler.name==AttachHandler.name)
class ActiveContainerLogs(ActiveHunter):
    def __init__(self, event):
        self.event = event

    def execute(self):
        pass
# def get_kubesystem_pod_container(self):
#     pods_data = json.loads(requests.get("https://{host}:{port}/pods".format(host=self.event.host, port=self.event.port), verify=False).text)['items']
#     # filter running kubesystem pod
#     kubesystem_pod = lambda pod: pod["metadata"]["namespace"] == "kube-system" and pod["status"]["phase"] == "Running"        
#     pod_data = (pod_data for pod_data in pods_data if kubesystem_pod(pod_data)).next()

#     container_data = (container_data for container_data in pod_data["spec"]["containers"]).next()
#     return pod_data["metadata"]["name"], container_data["name"]
