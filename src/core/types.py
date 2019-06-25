class HunterBase(object):
    publishedVulnerabilities = 0

    @staticmethod
    def parse_docs(docs):
        """returns tuple of (name, docs)"""
        if not docs:
            return __name__, "<no documentation>"
        docs = docs.strip().split('\n')
        for i, line in enumerate(docs):
            docs[i] = line.strip()
        return docs[0], ' '.join(docs[1:]) if len(docs[1:]) else "<no documentation>"

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


"""Kubernetes Components"""
class KubernetesCluster():
    """Kubernetes Cluster"""
    name = "Kubernetes Cluster"

class KubectlClient():
    """The kubectl client binary is used by the user to interact with the cluster"""
    name = "Kubectl Client"

class Kubelet(KubernetesCluster):
    """The kubelet is the primary "node agent" that runs on each node"""
    name = "Kubelet"


class Azure(KubernetesCluster):
    """Azure Cluster"""
    name = "Azure"


""" Categories """
class InformationDisclosure(object):
    name = "Information Disclosure"


class RemoteCodeExec(object):
    name = "Remote Code Execution"


class IdentityTheft(object):
    name = "Identity Theft"


class UnauthenticatedAccess(object):
    name = "Unauthenticated Access"


class AccessRisk(object):
    name = "Access Risk"


class PrivilegeEscalation(KubernetesCluster):
    name = "Privilege Escalation"

class DenialOfService(object):
    name = "Denial of Service"

from .events import handler # import is in the bottom to break import loops
