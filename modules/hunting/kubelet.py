import json
import logging
from enum import Enum

import requests
import urllib3

from ..events import handler
from ..events.types import (Vulnerability, Event, ReadOnlyKubeletEvent,
                            SecureKubeletEvent)
from ..discovery.kubelet import KubeletOpenHandler
from ..types import Hunter
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


""" dividing ports for seperate hunters """
@handler.subscribe(ReadOnlyKubeletEvent)
class ReadOnlyKubeletPortHunter(Hunter):
    def __init__(self, event):
        self.event = event

    def execute(self):
        pass
        
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
                return self.Handlers.CONTAINERLOGS.name
        
        # need further investigation on websockets protocol for further implementation
        def test_exec_container(self):
            # opens a stream to connect to using a web socket
            headers={"X-Stream-Protocol-Version": "v2.channel.k8s.io"}
            exec_url = self.path + self.Handlers.EXEC.value.format(
                podNamespace = self.pod.namespace,
                podID = self.pod.name,
                containerName = self.pod.container,
                cmd = "uname"
            )
            if "/cri/exec/" in self.session.get(exec_url, headers=headers, allow_redirects=False ,verify=False).text:
                return self.Handlers.EXEC.name

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
                cmd = "echo check"
            )
            output = requests.post(run_url, allow_redirects=False ,verify=False).text        
            if "echo" not in output and "check" in output:
                return self.Handlers.EXEC.name

        # returns list of currently running pods
        def test_running_pods(self):
            pods_url = self.path + self.Handlers.RUNNINGPODS.value
            if 'items' in json.loads(self.session.get(pods_url, verify=False).text).keys():
                return self.Handlers.RUNNINGPODS.name
        
        # need further investigation on the differences between attach and exec
        def test_attach_container(self):
            # headers={"X-Stream-Protocol-Version": "v2.channel.k8s.io"}
            attach_url = self.path + self.Handlers.ATTACH.value.format(
                podNamespace = self.pod.namespace,
                podID = self.pod.name,
                containerName = self.pod.container,
                cmd = "uname"
            )
            if "/cri/attach/" in self.session.get(attach_url, allow_redirects=False ,verify=False).text:
                return self.Handlers.ATTACH.name

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
        pod = self.get_self_pod() if self.event.pod else self.get_random_pod()
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
            handler_name = test_handler()
            if handler_name:
                self.publish_event(KubeletOpenHandler(handler=handler_name.lower()))

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

# def get_kubesystem_pod_container(self):
#     pods_data = json.loads(requests.get("https://{host}:{port}/pods".format(host=self.event.host, port=self.event.port), verify=False).text)['items']
#     # filter running kubesystem pod
#     kubesystem_pod = lambda pod: pod["metadata"]["namespace"] == "kube-system" and pod["status"]["phase"] == "Running"        
#     pod_data = (pod_data for pod_data in pods_data if kubesystem_pod(pod_data)).next()

#     container_data = (container_data for container_data in pod_data["spec"]["containers"]).next()
#     return pod_data["metadata"]["name"], container_data["name"]
