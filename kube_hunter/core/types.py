class HunterBase:
    publishedVulnerabilities = 0

    @staticmethod
    def parse_docs(docs):
        """returns tuple of (name, docs)"""
        if not docs:
            return __name__, "<no documentation>"
        docs = docs.strip().split("\n")
        for i, line in enumerate(docs):
            docs[i] = line.strip()
        return docs[0], " ".join(docs[1:]) if len(docs[1:]) else "<no documentation>"

    @classmethod
    def get_name(cls):
        name, _ = cls.parse_docs(cls.__doc__)
        return name

    def publish_event(self, event):
        handler.publish_event(event, caller=self)


class ActiveHunter(HunterBase):
    pass


class Hunter(HunterBase):
    pass


class Discovery(HunterBase):
    pass


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


class InformationDisclosure:
    name = "Information Disclosure"


class RemoteCodeExec:
    name = "Remote Code Execution"


class IdentityTheft:
    name = "Identity Theft"


class UnauthenticatedAccess:
    name = "Unauthenticated Access"


class AccessRisk:
    name = "Access Risk"


class PrivilegeEscalation(KubernetesCluster):
    name = "Privilege Escalation"


class DenialOfService:
    name = "Denial of Service"


# import is in the bottom to break import loops
from .events import handler  # noqa
