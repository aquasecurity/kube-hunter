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


from events import handler # import is in the bottom to break import loops