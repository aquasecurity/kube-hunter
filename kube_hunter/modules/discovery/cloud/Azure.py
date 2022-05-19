from kube_hunter.core.types import Discovery, Vulnerability, Event

class AzureMetadataApi(Vulnerability, Event):
    """Access to the Azure Metadata API exposes information about the machines associated with the cluster"""

    def __init__(self, cidr):
        Vulnerability.__init__(
            self,
            Azure,
            "Azure Metadata Exposure",
            category=InstanceMetadataApiTechnique,
            vid="KHV003",
        )
        self.cidr = cidr
        self.evidence = f"cidr: {cidr}"


