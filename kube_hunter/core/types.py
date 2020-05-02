import abc

from typing import ClassVar, Iterator, Tuple
from dataclasses import dataclass
from kube_hunter.core.pubsub.subscription import Event, Subscriber


class HunterBase(Subscriber, metaclass=abc.ABCMeta):
    published_vulnerabilities: ClassVar[int] = 0

    @classmethod
    def parse_docs(cls) -> Tuple[str, str]:
        """Returns tuple of (name, description)"""
        if not cls.__doc__:
            return cls.__name__, "Documentation unavailable"
        docs = [line.strip() for line in cls.__doc__.strip().split("\n")]
        header = docs[0]
        description = "\n".join(docs[1:]) or "Documentation unavailable"
        return header, description

    @classmethod
    def get_name(cls) -> str:
        doc = cls.__doc__ or ""
        return doc.strip().split("\n")[0].strip() or cls.__name__

    @abc.abstractmethod
    def execute(self) -> Iterator[Event]:
        pass


class ActiveHunter(HunterBase):
    pass


class Hunter(HunterBase):
    pass


class Discovery(HunterBase):
    pass


@dataclass
class Component:
    name: str
    description: str


KubernetesCluster = Component(name="Kubernetes Cluster", description="Kubernetes container orchestrstor")
KubectlClient = Component(
    name="Kubectl Client",
    description="The kubectl client binary is used by a user to interact with kubernetes clusters",
)
Kubelet = Component(name="Kubelet", description="Kubelet is an agent that runs on each kubernetes node")
AKSCluster = Component(name="AKS Cluster", description="Azure managed kubernetes cluster")


@dataclass
class Category:
    name: str
    severity: str


NoCategory = Category(name="", severity="")
InformationDisclosure = Category(name="Information Disclosure", severity="medium")
RemoteCodeExec = Category(name="Remote Code Execution", severity="high")
IdentityTheft = Category(name="Identity Theft", severity="high")
UnauthenticatedAccess = Category(name="Unauthenticated Access", severity="low")
AccessRisk = Category(name="Access Risk", severity="low")
PrivilegeEscalation = Category(name="Privilege Escalation", severity="high")
DenialOfService = Category(name="Denial of Service", severity="medium")


@dataclass
class Service:
    name: str
    path: str = ""
    secure: bool = True
    role: str = "Node"

    def __post_init__(self):
        if not self.path.startswith("/"):
            self.path = f"/{self.path}"

    def explain(self):
        return self.__doc__ or ""


@dataclass
class Vulnerability(Event):
    name: str
    component: Component
    vid: str = "None"  # TODO: make vid mandatory once migration is done
    category: Category = NoCategory
    evidence: str = ""
    role: str = "Node"
    description: str = ""

    def __post_init__(self):
        Event.__init__(self)

    def explain(self):
        return self.description or self.__doc__ or ""
