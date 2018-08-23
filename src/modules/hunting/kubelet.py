import json
import logging
from enum import Enum

import requests
import urllib3

from __main__ import config
from ...core.events import handler
from ...core.events.types import Vulnerability, Event
from ..discovery.kubelet import ReadOnlyKubeletEvent, SecureKubeletEvent
from ...core.types import Hunter, ActiveHunter, KubernetesCluster, Kubelet, InformationDisclosure, RemoteCodeExec, AccessRisk
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


""" Vulnerabilities """
class ExposedPodsHandler(Vulnerability, Event):
    """An attacker could view sensitive information about pods that are bound to a Node using the /pods endpoint"""
    def __init__(self, count):
        Vulnerability.__init__(self, Kubelet, "Exposed Pods", category=InformationDisclosure)    
        self.count = count
        self.evidence = "count: {}".format(self.count)
        
class AnonymousAuthEnabled(Vulnerability, Event):
    """The kubelet is misconfigured, potentially allowing secure access to all requests on the kubelet, without the need to authenticate"""
    def __init__(self):
        Vulnerability.__init__(self, Kubelet, "Anonymous Authentication", category=RemoteCodeExec)

class ExposedContainerLogsHandler(Vulnerability, Event):
    """Output logs from a running container are using the exposed /containerLogs endpoint"""
    def __init__(self):
        Vulnerability.__init__(self, Kubelet, "Exposed Container Logs", category=InformationDisclosure)    
    
class ExposedRunningPodsHandler(Vulnerability, Event):
    """Outputs a list of currently running pods, and some of their metadata, which can reveal sensitive information"""
    def __init__(self, count):
        Vulnerability.__init__(self, Kubelet, "Exposed Running Pods", category=InformationDisclosure)    
        self.count = count
        self.evidence = "{} running pods".format(self.count)

class ExposedExecHandler(Vulnerability, Event):
    """An attacker could run arbitrary commands on a container"""
    def __init__(self):
        Vulnerability.__init__(self, Kubelet, "Exposed Exec On Container", category=RemoteCodeExec)    

class ExposedRunHandler(Vulnerability, Event):
    """An attacker could run an arbitrary command inside a container"""
    def __init__(self):
        Vulnerability.__init__(self, Kubelet, "Exposed Run Inside Container", category=RemoteCodeExec)    

class ExposedPortForwardHandler(Vulnerability, Event):
    """An attacker could set port forwaring rule on a pod"""
    def __init__(self):
        Vulnerability.__init__(self, Kubelet, "Exposed Port Forward", category=RemoteCodeExec)    

class ExposedAttachHandler(Vulnerability, Event):
    """Opens a websocket that could enable an attacker to attach to a running container"""
    def __init__(self):
        Vulnerability.__init__(self, Kubelet, "Exposed Attaching To Container", category=RemoteCodeExec)    

class ExposedHealthzHandler(Vulnerability, Event):
    """By accessing the open /healthz handler, an attacker could get the cluster health state without authenticating"""
    def __init__(self, status):
        Vulnerability.__init__(self, Kubelet, "Cluster Health Disclosure", category=InformationDisclosure)    
        self.status = status
        self.evidence = "status: {}".format(self.status)

class K8sVersionDisclosure(Vulnerability, Event):
    """The kubernetes version could be obtained from logs in the /metrics endpoint"""
    def __init__(self, version):
        Vulnerability.__init__(self, Kubelet, "K8s Version Disclosure", category=InformationDisclosure)
        self.evidence = version
    
class PrivilegedContainers(Vulnerability, Event):
    """A Privileged container exist on a node. could expose the node/cluster to unwanted root operations"""
    def __init__(self, containers):
        Vulnerability.__init__(self, KubernetesCluster, "Privileged Container", category=AccessRisk)
        self.containers = containers
        self.evidence = "pod: {}, container: {}".format(containers[0][0], containers[0][1])
        

""" dividing ports for seperate hunters """
@handler.subscribe(ReadOnlyKubeletEvent)
class ReadOnlyKubeletPortHunter(Hunter):
    """Kubelet Readonly Ports Hunter
    Hunts specific endpoints on open ports in the readonly Kubelet server
    """
    def __init__(self, event):
        self.event = event
        self.path = "http://{}:{}/".format(self.event.host, self.event.port)
        self.pods_endpoint_data = ""

    def get_k8s_version(self):
        metrics = requests.get(self.path + "metrics").text
        for line in metrics.split("\n"):
            if line.startswith("kubernetes_build_info"):
                for info in line[line.find('{') + 1: line.find('}')].split(','):
                    k, v = info.split("=")
                    if k == "gitVersion":
                        return v.strip("\"")
    
    # returns list of tuples of Privileged container and their pod. 
    def find_privileged_containers(self):
        privileged_containers = list()
        if self.pods_endpoint_data:
            for pod in self.pods_endpoint_data["items"]:
                for container in pod["spec"]["containers"]:
                    if "securityContext" in container and "privileged" in container["securityContext"] and container["securityContext"]["privileged"]:
                        privileged_containers.append((pod["metadata"]["name"], container["name"]))
        return privileged_containers if len(privileged_containers) > 0 else None
    
    def get_pods_endpoint(self):
        response = requests.get(self.path + "pods")
        if "items" in response.text:
            return json.loads(response.text)

    def check_healthz_endpoint(self):
        r = requests.get(self.path + "healthz", verify=False)
        return r.text if r.status_code == 200 else False

    def execute(self):
        self.pods_endpoint_data = self.get_pods_endpoint()
        k8s_version = self.get_k8s_version()
        privileged_containers = self.find_privileged_containers()
        healthz = self.check_healthz_endpoint()
        if k8s_version:
            self.publish_event(K8sVersionDisclosure(version=k8s_version))
        if privileged_containers:
            self.publish_event(PrivilegedContainers(containers=privileged_containers))
        if healthz:
            self.publish_event(ExposedHealthzHandler(status=healthz))
        if self.pods_endpoint_data:
            self.publish_event(ExposedPodsHandler(count=len(self.pods_endpoint_data["items"])))

@handler.subscribe(SecureKubeletEvent)        
class SecureKubeletPortHunter(Hunter):
    """Kubelet Secure Ports Hunter
    Hunts specific endpoints on an open secured Kubelet
    """
    class DebugHandlers(object):    
        """ all methods will return the handler name if successfull """
        class Handlers(Enum):
            CONTAINERLOGS = "containerLogs/{podNamespace}/{podID}/{containerName}"                        # GET
            RUNNINGPODS = "runningpods"                                                                   # GET
            EXEC = "exec/{podNamespace}/{podID}/{containerName}?command={cmd}&input=1&output=1&tty=1"     # GET -> WebSocket 
            RUN = "run/{podNamespace}/{podID}/{containerName}?cmd={cmd}"                                  # POST, For legacy reasons, it uses different query param than exec.
            PORTFORWARD = "portForward/{podNamespace}/{podID}?port={port}"                                # GET/POST
            ATTACH = "attach/{podNamespace}/{podID}/{containerName}?command={cmd}&input=1&output=1&tty=1" # GET -> WebSocket

        def __init__(self, path, pod, session=None):
            self.path = path
            self.session = session if session else requests.Session()
            self.pod = pod
            
        # outputs logs from a specific container
        def test_container_logs(self):
            logs_url = self.path + self.Handlers.CONTAINERLOGS.value.format(
                podNamespace=self.pod["namespace"],
                podID=self.pod["name"],
                containerName=self.pod["container"]
            )
            return self.session.get(logs_url, verify=False).status_code == 200
        
        # need further investigation on websockets protocol for further implementation
        def test_exec_container(self):
            # opens a stream to connect to using a web socket
            headers={"X-Stream-Protocol-Version": "v2.channel.k8s.io"}
            exec_url = self.path + self.Handlers.EXEC.value.format(
                podNamespace=self.pod["namespace"],
                podID=self.pod["name"],
                containerName=self.pod["container"],
                cmd = ""
            )
            return "/cri/exec/" in self.session.get(exec_url, headers=headers, allow_redirects=False ,verify=False).text

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
                podNamespace=self.pod["namespace"],
                podID=self.pod["name"],
                port=80
            )
            self.session.get(pf_url, headers=headers, verify=False, stream=True).status_code == 200
            #TODO: what to return?

        # executes one command and returns output
        def test_run_container(self):
            run_url = self.path + self.Handlers.RUN.value.format(
                podNamespace=self.pod["namespace"],
                podID=self.pod["name"],
                containerName=self.pod["container"],
                cmd = ""
            )
            status_code = requests.post(run_url, allow_redirects=False, verify=False).status_code 
            return (status_code != 404 and status_code != 401)

        # returns list of currently running pods
        def test_running_pods(self):
            pods_url = self.path + self.Handlers.RUNNINGPODS.value
            r = self.session.get(pods_url, verify=False)
            return json.loads(r.text) if r.status_code == 200 else False

        # need further investigation on the differences between attach and exec
        def test_attach_container(self):
            # headers={"X-Stream-Protocol-Version": "v2.channel.k8s.io"}
            attach_url = self.path + self.Handlers.ATTACH.value.format(
                podNamespace=self.pod["namespace"],
                podID=self.pod["name"],
                containerName=self.pod["container"],
                cmd = ""
            )
            return "/cri/attach/" in self.session.get(attach_url, allow_redirects=False ,verify=False).text

    def __init__(self, event):
        self.event = event
        self.session = requests.Session()
        if self.event.secure:
            self.session.headers.update({"Authorization": "Bearer {}".format(self.event.auth_token)})
            # self.session.cert = self.event.client_cert
        self.path = "https://{}:{}/".format(self.event.host, 10250)
        self.kubehunter_pod = {"name": "kube-hunter", "namespace": "default", "container": "kube-hunter"}
        self.pods_endpoint_data = ""

    def get_pods_endpoint(self):
        response = self.session.get(self.path + "pods", verify=False)
        if "items" in response.text:
            return json.loads(response.text)

    def check_healthz_endpoint(self):
        r = requests.get(self.path + "healthz", verify=False)
        return r.text if r.status_code == 200 else False

    def execute(self):
        if self.event.anonymous_auth:
            self.publish_event(AnonymousAuthEnabled())

        self.pods_endpoint_data = self.get_pods_endpoint()
        healthz = self.check_healthz_endpoint() 
        if self.pods_endpoint_data:
            self.publish_event(ExposedPodsHandler(count=len(self.pods_endpoint_data["items"])))
        if healthz:
            self.publish_event(ExposedHealthzHandler(status=healthz)) 
        self.test_handlers()

    def test_handlers(self):
        # if kube-hunter runs in a pod, we test with kube-hunter's pod        
        pod = self.kubehunter_pod if config.pod else self.get_random_pod()
        if pod:
            debug_handlers = self.DebugHandlers(self.path, pod=pod, session=self.session)
            try:
                running_pods = debug_handlers.test_running_pods()
                if running_pods:
                    self.publish_event(ExposedRunningPodsHandler(count=len(running_pods["items"])))            
                if debug_handlers.test_container_logs():
                    self.publish_event(ExposedContainerLogsHandler())
                if debug_handlers.test_exec_container():
                    self.publish_event(ExposedExecHandler())      
                if debug_handlers.test_run_container():
                    self.publish_event(ExposedRunHandler())
                if debug_handlers.test_port_forward():
                    self.publish_event(ExposedPortForwardHandler()) # not implemented            
                if debug_handlers.test_attach_container():
                    self.publish_event(ExposedAttachHandler())
            except Exception as ex:
                logging.debug(str(ex.message))
        else:
            pass # no pod to check on.

    # trying to get a pod from default namespace, if doesnt exist, gets a kube-system one
    def get_random_pod(self):
        if self.pods_endpoint_data: 
            pods_data = self.pods_endpoint_data["items"]
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
                "namespace": pod_data["metadata"]["namespace"]
            }

@handler.subscribe(ExposedRunHandler)
class ProveRunHandler(ActiveHunter):
    """Kubelet Run Hunter
    Executes uname inside of a random container
    """
    def __init__(self, event):
        self.event = event
    
    def run(self, command, container):
        run_url = "https://{host}:{port}/run/{podNamespace}/{podID}/{containerName}".format(
            host=self.event.host,
            port=self.event.port,            
            podNamespace=container["namespace"],
            podID=container["pod"],
            containerName=container["name"]
        )
        return requests.post(run_url, verify=False, params={'cmd': command}).text

    def execute(self):
        pods_raw = requests.get("https://{host}:{port}/pods".format(host=self.event.host, port=self.event.port), verify=False).text
        if "items" in pods_raw:
            pods_data = json.loads(pods_raw)['items']
            for pod_data in pods_data:
                container_data = next((container_data for container_data in pod_data["spec"]["containers"]), None)
                if container_data:
                    output = self.run("uname -a", container={
                        "namespace": pod_data["metadata"]["namespace"],
                        "pod": pod_data["metadata"]["name"],
                        "name": container_data["name"]                    
                    })
                    if output and "exited with" not in output:
                        self.event.evidence = "uname -a: " + output
                        break

@handler.subscribe(ExposedContainerLogsHandler)
class ProveContainerLogsHandler(ActiveHunter):
    """Kubelet Container Logs Hunter
    Retrieves logs from a random container 
    """
    def __init__(self, event):
        self.event = event
        protocol = "https" if self.event.port == 10250 else "http"
        self.base_url = "{protocol}://{host}:{port}".format(protocol=protocol, host=self.event.host, port=self.event.port)

    def execute(self):
        pods_raw = requests.get(self.base_url + "/pods", verify=False).text
        if "items" in pods_raw:
            pods_data = json.loads(pods_raw)['items']
            for pod_data in pods_data:
                container_data = next((container_data for container_data in pod_data["spec"]["containers"]), None)
                if container_data:
                    output = requests.get(self.base_url + "/containerLogs/{podNamespace}/{podID}/{containerName}".format(
                        podNamespace=pod_data["metadata"]["namespace"],
                        podID=pod_data["metadata"]["name"],
                        containerName=container_data["name"]
                    ), verify=False)
                    if output.status_code == 200 and output.text:
                        self.event.evidence = "{}: {}".format(
                            container_data["name"],
                            output.text.encode('utf-8')
                        )
                        return
