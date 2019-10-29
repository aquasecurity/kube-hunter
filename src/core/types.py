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


""" Categories 

Defines the category of each vulnerability 
That could be exploited by an attacker.
"""
class InformationDisclosure(object):
    """ Security issue where the attacker can
    gain access to sensitive information in
    the Virtual Machine. 
    """
    name = "Information Disclosure"


class RemoteCodeExec(object):
    """ Remote execution of code, it is, you can
    execute code in the VM from anywhere, 
    wether arbitrary code or specific code.
    """
    name = "Remote Code Execution"


class IdentityTheft(object):
    """ This isssue allows the attacker 
    to gain the identity of some other 
    user without permission. 
    """
    name = "Identity Theft"


class UnauthenticatedAccess(object):
    """ This issue allows the attacker to
    access some zone of the application
    or the Virtual Machine without any
    authentication. 
    """
    name = "Unauthenticated Access"


class AccessRisk(object):
    """ This issue may represent a possibility
    of someone gain access to the system, it is,
    anything that changes the behaviour of the
    system may give the attacker a possible 
    vulnerability to be exploited
    """
    name = "Access Risk"


class PrivilegeEscalation(KubernetesCluster):
    """ This issue means that an attacker that
    exploits the failure may reach a higher 
    privilige than the privilege that the user
    should have. For example, a common privilege
    escalation is when a common user reaches the
    root level.
    """
    name = "Privilege Escalation"

class DenialOfService(object):
    """ That issue allows the attacker
    to deny the application's service.
    Some common attacks are deny of HTTP
    requests, so no remote user can make
    use of the application's service, or 
    shutdown the server so no one can access
    the machine, or lock the application
    into a loop so no one else can receive
    a response from the service.
    """
    name = "Denial of Service"

from .events import handler # import is in the bottom to break import loops
