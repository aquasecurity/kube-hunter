class HunterBase(object):
    publishedEvents = 0


class ActiveHunter(HunterBase):
    def publish_event(self, event):
        handler.publish_event(event, caller=self)


class Hunter(HunterBase):
    def publish_event(self, event):
        handler.publish_event(event, caller=self)


class DiscoveryHunter(Hunter):
    pass


"""Kubernetes Components"""
class KubernetesCluster():
    """Kubernetes Cluster"""
    name = "Kubernetes Cluster"


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
