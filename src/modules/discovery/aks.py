import os
import json
import logging
import sys

import requests
from netaddr import IPNetwork

from __main__ import config

from ...core.events import handler
from ...core.events.types import Event, NewHostEvent, Vulnerability
from ...core.types import Discovery, InformationDisclosure, Azure, CloudTypes

from .hosts import RunningPodOnCloud, HostDiscoveryUtils

class AzureMetadataApi(Vulnerability, Event):
    """Access to the Azure Metadata API exposes information about the machines associated with the cluster"""
    def __init__(self, cidr):
        Vulnerability.__init__(self, Azure, "Azure Metadata Exposure", category=InformationDisclosure)
        self.cidr = cidr
        self.evidence = "cidr: {}".format(cidr)

@handler.subscribe(RunningPodOnCloud, predicate=lambda x: x.cloud == CloudTypes.AKS)
class AzureHostDiscovery(Discovery):
    """Azure Host Discovery 
    Discovers AKS specific nodes when running as a pod in Azure
    """
    def __init__(self, event):
        self.event = event
    
    def is_azure_api(self):
        try:
            logging.debug("From pod attempting to access Azure Metadata API")
            if requests.get("http://169.254.169.254/metadata/instance?api-version=2017-08-01", headers={"Metadata":"true"}, timeout=5).status_code == 200:
                return True
        except requests.exceptions.ConnectionError:
            return False
    
    # quering azure's interface metadata api | works only from a pod
    def azure_metadata_subnets_discovery(self):
        logging.debug("From pod attempting to access azure's metadata")
        machine_metadata = json.loads(requests.get("http://169.254.169.254/metadata/instance?api-version=2017-08-01", headers={"Metadata":"true"}).text)
        subnets = list()
        for interface in machine_metadata["network"]["interface"]:
            address, subnet = interface["ipv4"]["subnet"][0]["address"], interface["ipv4"]["subnet"][0]["prefix"]
            logging.debug("From pod discovered subnet {0}/{1}".format(address, subnet if not config.quick else "24"))
            subnets.append([address,subnet if not config.quick else "24"])
        
        self.publish_event(AzureMetadataApi(cidr="{}/{}".format(address, subnet)))
        return subnets

    def execute(self):
        if self.is_azure_api():
            for subnet in self.azure_metadata_subnets_discovery():
                logging.debug("Azure subnet scanning {0}/{1}".format(subnet[0], subnet[1]))
                for ip in HostDiscoveryUtils.generate_subnet(ip=subnet[0], sn=subnet[1]):
                    self.publish_event(NewHostEvent(host=ip, cloud=CloudTypes.AKS))
    