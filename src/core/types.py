class ActiveHunter(object):    
    def publish_event(self, event):
        handler.publish_event(event, caller=self)


class Hunter(object):
    def publish_event(self, event):
        handler.publish_event(event, caller=self)


"""Kubernetes Components"""
class KubernetesCluster():
    """Kubernetes Cluster"""
    name = "Kubernetes Cluster"

class Kubelet(KubernetesCluster):
    """The kubelet is the primary "node agent" that runs on each node"""
    name = "Kubelet"


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


from events import handler # import is in the bottom to break import loops