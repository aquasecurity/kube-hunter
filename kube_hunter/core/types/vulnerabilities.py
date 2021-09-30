"""
Vulnerabilities are divided into 2 main categories.

MITRE Category
--------------
Vulnerability that correlates to a method in the official MITRE ATT&CK matrix for kubernetes

CVE Category
-------------
"General" category definition. The category is usually determined by the severity of the CVE
"""


class MITRECategory:
    @classmethod
    def get_name(cls):
        """
        Returns the full name of MITRE technique: <MITRE CATEGORY> // <MITRE TECHNIQUE>
        Should only be used on a direct technique class at the end of the MITRE inheritance chain.

        Example inheritance:
        MITRECategory -> InitialAccessCategory -> ExposedSensitiveInterfacesTechnique
        """
        inheritance_chain = cls.__mro__
        if len(inheritance_chain) >= 4:
            # -3 == index of mitreCategory class. (object class is first)
            mitre_category_class = inheritance_chain[-3]
        return f"{mitre_category_class.name} // {cls.name}"


class CVECategory:
    @classmethod
    def get_name(cls):
        """
        Returns the full name of the category: CVE // <CVE Category name>
        """
        return f"CVE // {cls.name}"


"""
MITRE ATT&CK Technique Categories
"""


class InitialAccessCategory(MITRECategory):
    name = "Initial Access"


class ExecutionCategory(MITRECategory):
    name = "Execution"


class PersistenceCategory(MITRECategory):
    name = "Persistence"


class PrivilegeEscalationCategory(MITRECategory):
    name = "Privilege Escalation"


class DefenseEvasionCategory(MITRECategory):
    name = "Defense Evasion"


class CredentialAccessCategory(MITRECategory):
    name = "Credential Access"


class DiscoveryCategory(MITRECategory):
    name = "Discovery"


class LateralMovementCategory(MITRECategory):
    name = "Lateral Movement"


class CollectionCategory(MITRECategory):
    name = "Collection"


class ImpactCategory(MITRECategory):
    name = "Impact"


"""
MITRE ATT&CK Techniques
"""


class GeneralSensitiveInformationTechnique(InitialAccessCategory):
    name = "General Sensitive Information"


class ExposedSensitiveInterfacesTechnique(InitialAccessCategory):
    name = "Exposed sensitive interfaces"


class MountServicePrincipalTechnique(CredentialAccessCategory):
    name = "Mount service principal"


class ListK8sSecretsTechnique(CredentialAccessCategory):
    name = "List K8S secrets"


class AccessContainerServiceAccountTechnique(CredentialAccessCategory):
    name = "Access container service account"


class AccessK8sApiServerTechnique(DiscoveryCategory):
    name = "Access the K8S API Server"


class AccessKubeletAPITechnique(DiscoveryCategory):
    name = "Access Kubelet API"


class AccessK8sDashboardTechnique(DiscoveryCategory):
    name = "Access Kubernetes Dashboard"


class InstanceMetadataApiTechnique(DiscoveryCategory):
    name = "Instance Metadata API"


class ExecIntoContainerTechnique(ExecutionCategory):
    name = "Exec into container"


class SidecarInjectionTechnique(ExecutionCategory):
    name = "Sidecar injection"


class NewContainerTechnique(ExecutionCategory):
    name = "New container"


class GeneralPersistenceTechnique(PersistenceCategory):
    name = "General Peristence"


class HostPathMountPrivilegeEscalationTechnique(PrivilegeEscalationCategory):
    name = "hostPath mount"


class PrivilegedContainerTechnique(PrivilegeEscalationCategory):
    name = "Privileged container"


class ClusterAdminBindingTechnique(PrivilegeEscalationCategory):
    name = "Cluser-admin binding"


class ARPPoisoningTechnique(LateralMovementCategory):
    name = "ARP poisoning and IP spoofing"


class CoreDNSPoisoningTechnique(LateralMovementCategory):
    name = "CoreDNS poisoning"


class DataDestructionTechnique(ImpactCategory):
    name = "Data Destruction"


class GeneralDefenseEvasionTechnique(DefenseEvasionCategory):
    name = "General Defense Evasion"


class ConnectFromProxyServerTechnique(DefenseEvasionCategory):
    name = "Connect from Proxy server"


"""
CVE Categories
"""


class CVERemoteCodeExecutionCategory(CVECategory):
    name = "Remote Code Execution (CVE)"


class CVEPrivilegeEscalationCategory(CVECategory):
    name = "Privilege Escalation (CVE)"


class CVEDenialOfServiceTechnique(CVECategory):
    name = "Denial Of Service (CVE)"
