class KubernetesCluster:
    """Kubernetes Cluster"""

    name = "Kubernetes Cluster"


class KubectlClient:
    """The kubectl client binary is used by the user to interact with the cluster"""

    name = "Kubectl Client"


class Kubelet(KubernetesCluster):
    """The kubelet is the primary "node agent" that runs on each node"""

    name = "Kubelet"


class AWS(KubernetesCluster):
    """AWS Cluster"""

    name = "AWS"


class Azure(KubernetesCluster):
    """Azure Cluster"""

    name = "Azure"
