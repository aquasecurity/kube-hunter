class KubernetesCluster:
    """Kubernetes Cluster"""

    name = "Kubernetes Cluster"

class CloudProvider:
    name = "Cloud Provider"


class KubectlClient:
    """The kubectl client binary is used by the user to interact with the cluster"""

    name = "Kubectl Client"


class Kubelet(KubernetesCluster):
    """The kubelet is the primary "node agent" that runs on each node"""

    name = "Kubelet"


class BareMetal(CloudProvider):
    """AWS Cluster"""

    name = "Bare Metal Installation"

class Azure(CloudProvider):
    """Azure Cluster"""

    name = "AKS Cluster"
