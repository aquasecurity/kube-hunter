import json
import logging
from enum import Enum

import re
import requests
import urllib3

from kube_hunter.conf import config
from kube_hunter.core.events import handler
from kube_hunter.core.events.types import Vulnerability, Event, K8sVersionDisclosure
from kube_hunter.core.types import Hunter, ActiveHunter, KubernetesCluster, Kubelet, InformationDisclosure, RemoteCodeExec, AccessRisk
from kube_hunter.modules.discovery.kubelet import ReadOnlyKubeletEvent, SecureKubeletEvent

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


""" Vulnerabilities """
class ExposedPodsHandler(Vulnerability, Event):
    """An attacker could view sensitive information about pods that are bound to a Node using the /pods endpoint"""
    def __init__(self, pods):
        Vulnerability.__init__(self, Kubelet, "Exposed Pods", category=InformationDisclosure)
        self.pods = pods
        self.evidence = "count: {}".format(len(self.pods))


class AnonymousAuthEnabled(Vulnerability, Event):
    """The kubelet is misconfigured, potentially allowing secure access to all requests on the kubelet, without the need to authenticate"""
    def __init__(self):
        Vulnerability.__init__(self, Kubelet, "Anonymous Authentication", category=RemoteCodeExec, vid="KHV036")


class ExposedContainerLogsHandler(Vulnerability, Event):
    """Output logs from a running container are using the exposed /containerLogs endpoint"""
    def __init__(self):
        Vulnerability.__init__(self, Kubelet, "Exposed Container Logs", category=InformationDisclosure, vid="KHV037")


class ExposedRunningPodsHandler(Vulnerability, Event):
    """Outputs a list of currently running pods, and some of their metadata, which can reveal sensitive information"""
    def __init__(self, count):
        Vulnerability.__init__(self, Kubelet, "Exposed Running Pods", category=InformationDisclosure, vid="KHV038")
        self.count = count
        self.evidence = "{} running pods".format(self.count)


class ExposedExecHandler(Vulnerability, Event):
    """An attacker could run arbitrary commands on a container"""
    def __init__(self):
        Vulnerability.__init__(self, Kubelet, "Exposed Exec On Container", category=RemoteCodeExec, vid="KHV039")


class ExposedRunHandler(Vulnerability, Event):
    """An attacker could run an arbitrary command inside a container"""
    def __init__(self):
        Vulnerability.__init__(self, Kubelet, "Exposed Run Inside Container", category=RemoteCodeExec, vid="KHV040")


class ExposedPortForwardHandler(Vulnerability, Event):
    """An attacker could set port forwarding rule on a pod"""
    def __init__(self):
        Vulnerability.__init__(self, Kubelet, "Exposed Port Forward", category=RemoteCodeExec, vid="KHV041")


class ExposedAttachHandler(Vulnerability, Event):
    """Opens a websocket that could enable an attacker to attach to a running container"""
    def __init__(self):
        Vulnerability.__init__(self, Kubelet, "Exposed Attaching To Container", category=RemoteCodeExec, vid="KHV042")


class ExposedHealthzHandler(Vulnerability, Event):
    """By accessing the open /healthz handler, an attacker could get the cluster health state without authenticating"""
    def __init__(self, status):
        Vulnerability.__init__(self, Kubelet, "Cluster Health Disclosure", category=InformationDisclosure, vid="KHV043")
        self.status = status
        self.evidence = "status: {}".format(self.status)


class PrivilegedContainers(Vulnerability, Event):
    """A Privileged container exist on a node. could expose the node/cluster to unwanted root operations"""
    def __init__(self, containers):
        Vulnerability.__init__(self, KubernetesCluster, "Privileged Container", category=AccessRisk, vid="KHV044")
        self.containers = containers
        self.evidence = "pod: {}, container: {}, count: {}".format(containers[0][0], containers[0][1], len(containers))


class ExposedSystemLogs(Vulnerability, Event):
    """System logs are exposed from the /logs endpoint on the kubelet"""
    def __init__(self):
        Vulnerability.__init__(self, Kubelet, "Exposed System Logs", category=InformationDisclosure, vid="KHV045")


class ExposedKubeletCmdline(Vulnerability, Event):
    """Commandline flags that were passed to the kubelet can be obtained from the pprof endpoints"""
    def __init__(self, cmdline):
        Vulnerability.__init__(self, Kubelet, "Exposed Kubelet Cmdline", category=InformationDisclosure, vid="KHV046")
        self.cmdline = cmdline
        self.evidence = "cmdline: {}".format(self.cmdline)


""" Enum containing all of the kubelet handlers """
class KubeletHandlers(Enum):
    PODS = "pods"                                                                                 # GET
    CONTAINERLOGS = "containerLogs/{pod_namespace}/{pod_id}/{container_name}"                        # GET
    RUNNINGPODS = "runningpods"                                                                   # GET
    EXEC = "exec/{pod_namespace}/{pod_id}/{container_name}?command={cmd}&input=1&output=1&tty=1"     # GET -> WebSocket
    RUN = "run/{pod_namespace}/{pod_id}/{container_name}?cmd={cmd}"                                  # POST, For legacy reasons, it uses different query param than exec.
    PORTFORWARD = "portForward/{pod_namespace}/{pod_id}?port={port}"                                # GET/POST
    ATTACH = "attach/{pod_namespace}/{pod_id}/{container_name}?command={cmd}&input=1&output=1&tty=1" # GET -> WebSocket
    LOGS = "logs/{path}"                                                                          # GET
    PPROF_CMDLINE = "debug/pprof/cmdline"                                                         # GET


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
        logging.debug("Passive hunter is attempting to find kubernetes version")
        metrics = requests.get(self.path + "metrics").text
        for line in metrics.split("\n"):
            if line.startswith("kubernetes_build_info"):
                for info in line[line.find('{') + 1: line.find('}')].split(','):
                    k, v = info.split("=")
                    if k == "gitVersion":
                        return v.strip("\"")

    # returns list of tuples of Privileged container and their pod.
    def find_privileged_containers(self):
        logging.debug("Passive hunter is attempting to find privileged containers and their pods")
        privileged_containers = list()
        if self.pods_endpoint_data:
            for pod in self.pods_endpoint_data["items"]:
                for container in pod["spec"]["containers"]:
                    if "securityContext" in container and "privileged" in container["securityContext"] and container["securityContext"]["privileged"]:
                        privileged_containers.append((pod["metadata"]["name"], container["name"]))
        return privileged_containers if len(privileged_containers) > 0 else None

    def get_pods_endpoint(self):
        logging.debug("Attempting to find pods endpoints")
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
            self.publish_event(K8sVersionDisclosure(version=k8s_version, from_endpoint="/metrics", extra_info="on the Kubelet"))
        if privileged_containers:
            self.publish_event(PrivilegedContainers(containers=privileged_containers))
        if healthz:
            self.publish_event(ExposedHealthzHandler(status=healthz))
        if self.pods_endpoint_data:
            self.publish_event(ExposedPodsHandler(pods=self.pods_endpoint_data["items"]))


@handler.subscribe(SecureKubeletEvent)
class SecureKubeletPortHunter(Hunter):
    """Kubelet Secure Ports Hunter
    Hunts specific endpoints on an open secured Kubelet
    """
    class DebugHandlers(object):
        """ all methods will return the handler name if successful """
        def __init__(self, path, pod, session=None):
            self.path = path
            self.session = session if session else requests.Session()
            self.pod = pod

        # outputs logs from a specific container
        def test_container_logs(self):
            logs_url = self.path + KubeletHandlers.CONTAINERLOGS.value.format(
                pod_namespace=self.pod["namespace"],
                pod_id=self.pod["name"],
                container_name=self.pod["container"]
            )
            return self.session.get(logs_url, verify=False).status_code == 200

        # need further investigation on websockets protocol for further implementation
        def test_exec_container(self):
            # opens a stream to connect to using a web socket
            headers={"X-Stream-Protocol-Version": "v2.channel.k8s.io"}
            exec_url = self.path + KubeletHandlers.EXEC.value.format(
                pod_namespace=self.pod["namespace"],
                pod_id=self.pod["name"],
                container_name=self.pod["container"],
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
            pf_url = self.path + KubeletHandlers.PORTFORWARD.value.format(
                pod_namespace=self.pod["namespace"],
                pod_id=self.pod["name"],
                port=80
            )
            self.session.get(pf_url, headers=headers, verify=False, stream=True).status_code == 200
            #TODO: what to return?

        # executes one command and returns output
        def test_run_container(self):
            run_url = self.path + KubeletHandlers.RUN.value.format(
                pod_namespace='test',
                pod_id='test',
                container_name='test',
                cmd = ""
            )
            # if we get a Method Not Allowed, we know we passed Authentication and Authorization.
            return self.session.get(run_url, verify=False).status_code == 405

        # returns list of currently running pods
        def test_running_pods(self):
            pods_url = self.path + KubeletHandlers.RUNNINGPODS.value
            r = self.session.get(pods_url, verify=False)
            return json.loads(r.text) if r.status_code == 200 else False

        # need further investigation on the differences between attach and exec
        def test_attach_container(self):
            # headers={"X-Stream-Protocol-Version": "v2.channel.k8s.io"}
            attach_url = self.path + KubeletHandlers.ATTACH.value.format(
                pod_namespace=self.pod["namespace"],
                pod_id=self.pod["name"],
                container_name=self.pod["container"],
                cmd = ""
            )
            return "/cri/attach/" in self.session.get(attach_url, allow_redirects=False ,verify=False).text

        # checks access to logs endpoint
        def test_logs_endpoint(self):
            logs_url = self.session.get(self.path + KubeletHandlers.LOGS.value.format(
                path=""
            )).text
            return "<pre>" in logs_url

        # returns the cmd line used to run the kubelet
        def test_pprof_cmdline(self):
            cmd = self.session.get(self.path + KubeletHandlers.PPROF_CMDLINE.value, verify=False)
            return cmd.text if cmd.status_code == 200 else None


    def __init__(self, event):
        self.event = event
        self.session = requests.Session()
        if self.event.secure:
            self.session.headers.update({"Authorization": "Bearer {}".format(self.event.auth_token)})
            # self.session.cert = self.event.client_cert
        # copy session to event
        self.event.session = self.session
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
            self.publish_event(ExposedPodsHandler(pods=self.pods_endpoint_data["items"]))
        if healthz:
            self.publish_event(ExposedHealthzHandler(status=healthz))
        self.test_handlers()

    def test_handlers(self):
        # if kube-hunter runs in a pod, we test with kube-hunter's pod
        pod = self.kubehunter_pod if config.pod else self.get_random_pod()
        if pod:
            debug_handlers = self.DebugHandlers(self.path, pod=pod, session=self.session)
            try:
                # TODO: use named expressions, introduced in python3.8
                running_pods = debug_handlers.test_running_pods()
                if running_pods:
                    self.publish_event(ExposedRunningPodsHandler(count=len(running_pods["items"])))
                cmdline = debug_handlers.test_pprof_cmdline()
                if cmdline:
                    self.publish_event(ExposedKubeletCmdline(cmdline=cmdline))
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
                if debug_handlers.test_logs_endpoint():
                    self.publish_event(ExposedSystemLogs())
            except Exception as ex:
                logging.debug(str(ex))
        else:
            pass # no pod to check on.

    # trying to get a pod from default namespace, if doesn't exist, gets a kube-system one
    def get_random_pod(self):
        if self.pods_endpoint_data:
            pods_data = self.pods_endpoint_data["items"]
            # filter running kubesystem pod
            is_default_pod = lambda pod: pod["metadata"]["namespace"] == "default" and pod["status"]["phase"] == "Running"
            is_kubesystem_pod = lambda pod: pod["metadata"]["namespace"] == "kube-system" and pod["status"]["phase"] == "Running"
            pod_data = next((pod_data for pod_data in pods_data if is_default_pod(pod_data)), None)
            if not pod_data:
                pod_data = next((pod_data for pod_data in pods_data if is_kubesystem_pod(pod_data)), None)

            if pod_data:
                container_data = next((container_data for container_data in pod_data["spec"]["containers"]), None)
                if container_data:
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
        self.base_path = "https://{host}:{port}/".format(host=self.event.host, port=self.event.port)

    def run(self, command, container):
        run_url = KubeletHandlers.RUN.value.format(
            pod_namespace=container["namespace"],
            pod_id=container["pod"],
            container_name=container["name"],
            cmd=command
        )
        return self.event.session.post(self.base_path + run_url, verify=False).text

    def execute(self):
        pods_raw = self.event.session.get(self.base_path + KubeletHandlers.PODS.value, verify=False).text
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
        self.base_url = "{protocol}://{host}:{port}/".format(protocol=protocol, host=self.event.host, port=self.event.port)

    def execute(self):
        pods_raw = self.event.session.get(self.base_url + KubeletHandlers.PODS.value, verify=False).text
        if "items" in pods_raw:
            pods_data = json.loads(pods_raw)['items']
            for pod_data in pods_data:
                container_data = next((container_data for container_data in pod_data["spec"]["containers"]), None)
                if container_data:
                    output = requests.get(self.base_url + KubeletHandlers.CONTAINERLOGS.value.format(
                        pod_namespace=pod_data["metadata"]["namespace"],
                        pod_id=pod_data["metadata"]["name"],
                        container_name=container_data["name"]
                    ), verify=False)
                    if output.status_code == 200 and output.text:
                        self.event.evidence = "{}: {}".format(
                            container_data["name"],
                            output.text.encode('utf-8')
                        )
                        return

@handler.subscribe(ExposedSystemLogs)
class ProveSystemLogs(ActiveHunter):
    """Kubelet System Logs Hunter
    Retrieves commands from host's system audit
    """
    def __init__(self, event):
        self.event = event
        self.base_url = "https://{host}:{port}/".format(host=self.event.host, port=self.event.port)

    def execute(self):
        audit_logs = self.event.session.get(self.base_url + KubeletHandlers.LOGS.value.format(
            path="audit/audit.log"
        ), verify=False).text
        logging.debug("accessed audit log of host: {}".format(audit_logs[:10]))
        # iterating over proctitles and converting them into readable strings
        proctitles = list()
        for proctitle in re.findall(r"proctitle=(\w+)", audit_logs):
            proctitles.append(bytes.fromhex(proctitle).decode('utf-8').replace("\x00", " "))
        self.event.proctitles = proctitles
        self.event.evidence = "audit log: {}".format('; '.join(proctitles))
