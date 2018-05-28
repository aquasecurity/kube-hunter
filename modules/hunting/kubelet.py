import json
import logging
from enum import Enum

import requests
import urllib3

from ..events import handler
from ..events.types import (KubeletDebugHandler, ReadOnlyKubeletEvent,
                            SecureKubeletEvent)
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
class SecurePortKubeletHunter(Hunter):
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

        def __init__(self, host, **kargs):
            self.pod = self.PodData(**kargs)
            self.path = "https://{}:{}/".format(host, 10250)
            
        # outputs logs from a specific container
        def get_container_logs(self):
            logs_url = self.path + self.Handlers.CONTAINERLOGS.value.format(
                podNamespace=self.pod.namespace,
                podID=self.pod.name,
                containerName=self.pod.container
            )
            if requests.get(logs_url, verify=False).status_code == 200:
                return "containerLogs/"
        
        # need further investigation on websockets protocol for further implementation
        def get_exec_container(self):
            # opens a stream to connect to using a web socket
            headers={"X-Stream-Protocol-Version": "v2.channel.k8s.io"}
            exec_url = self.path + self.Handlers.EXEC.value.format(
                podNamespace = self.pod.namespace,
                podID = self.pod.name,
                containerName = self.pod.container,
                cmd = "uname"
            )
            if "/cri/exec/" in requests.get(exec_url, headers=headers, allow_redirects=False ,verify=False).text:
                return "exec/"

        # need further investigation on websockets protocol for further implementation
        def get_port_forward(self):
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
            requests.get(pf_url, headers=headers, verify=False, stream=True).status_code == 200
            #TODO: what to return?

        # executes one command and returns output
        def get_run_container(self):
            run_url = self.path + self.Handlers.RUN.value.format(
                podNamespace = self.pod.namespace,
                podID = self.pod.name,
                containerName = self.pod.container,
                cmd = "echo check"
            )
            output = requests.post(run_url, allow_redirects=False ,verify=False).text        
            if "echo" not in output and "check" in output:
                return "run/"

        # returns list of currently running pods
        def get_running_pods(self):
            pods_url = self.path + self.Handlers.RUNNINGPODS.value
            if 'items' in json.loads(requests.get(pods_url, verify=False).text).keys():
                return "runningpods/"
        
        # need further investigation on the differences between attach and exec
        def get_attach_container(self):
            # headers={"X-Stream-Protocol-Version": "v2.channel.k8s.io"}
            attach_url = self.path + self.Handlers.ATTACH.value.format(
                podNamespace = self.pod.namespace,
                podID = self.pod.name,
                containerName = self.pod.container,
                cmd = "uname"
            )
            if "/cri/attach/" in requests.get(attach_url, allow_redirects=False ,verify=False).text:
                return "attach/"

    def __init__(self, event):
        self.event = event
        self.debug_handlers = self.DebugHandlers(self.event.host, **self.get_self_pod())

    def execute(self):
        self.test_debugging_handlers()

    def test_debugging_handlers(self):
        test_handlers = [
            self.debug_handlers.get_container_logs, 
            self.debug_handlers.get_exec_container,
            self.debug_handlers.get_run_container,
            self.debug_handlers.get_running_pods,
            self.debug_handlers.get_port_forward,
            self.debug_handlers.get_attach_container
        ]
        for test_handler in test_handlers:
            output = test_handler()
            if output:
                self.publish_event(KubeletDebugHandler(desc=output))

    def get_self_pod(self):
        return {"name": "test-escalate", 
                "namespace": "default", 
                "container": "ubuntu"}


# def get_kubesystem_pod_container(self):
#     pods_data = json.loads(requests.get("https://{host}:{port}/pods".format(host=self.event.host, port=self.event.port), verify=False).text)['items']
#     # filter running kubesystem pod
#     kubesystem_pod = lambda pod: pod["metadata"]["namespace"] == "kube-system" and pod["status"]["phase"] == "Running"        
#     pod_data = (pod_data for pod_data in pods_data if kubesystem_pod(pod_data)).next()

#     container_data = (container_data for container_data in pod_data["spec"]["containers"]).next()
#     return pod_data["metadata"]["name"], container_data["name"]
