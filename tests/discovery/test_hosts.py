import requests_mock
import time
from queue import Empty

from src.modules.discovery.aks import AzureHostDiscovery, AzureMetadataApi
from src.modules.discovery.hosts import HostScanEvent, RunningPodOnCloud, FromPodHostDiscovery
from src.core.events.types import Event, NewHostEvent
from src.core.events import handler
from src.core.types import CloudTypes

from __main__ import config

# global variables for cloud discovery check
aws_triggered = False
azure_triggered = False

def test_AzureHostDiscovery():
    config.remote = None
    config.cidr = None
    config.pod = True
    with requests_mock.Mocker() as m:
        f = FromPodHostDiscovery(HostScanEvent())
        m.get("https://canhazip.com", text="1.2.3.4")
        m.get("https://www.azurespeed.com/api/region?ipOrUrl=1.2.3.4", text="""{
            "cloud": "Azure",
            "regionId": null,
            "region": null,
            "location": null,
            "ipAddress": "1.2.3.4"}""")

        # Test that we generate NewHostEvent for the addresses reported by the Azure Metadata API
        m.get("http://169.254.169.254/metadata/instance?api-version=2017-08-01", \
            text='{"network":{"interface":[{"ipv4":{"subnet":[{"address": "3.4.5.6", "prefix": "255.255.255.252"}]}}]}}')
    
        f.execute()
        time.sleep(0.1)
        assert azure_triggered

def test_AWSPodDiscovery():
    with requests_mock.Mocker() as m:
        e = HostScanEvent()
        config.remote = None
        config.cidr = None
        config.pod = True

        f = FromPodHostDiscovery(e)
        m.get("https://canhazip.com", text="1.2.3.4")
        m.get("https://www.azurespeed.com/api/region?ipOrUrl=1.2.3.4", text="""{
            "cloud": "AWS",
            "regionId": null,
            "region": null,
            "location": null,
            "ipAddress": "1.2.3.4"}""")
        f.execute()
        time.sleep(0.1)
        assert aws_triggered


@handler.subscribe(RunningPodOnCloud, predicate = lambda x: x.cloud == CloudTypes.EKS)
class testAWSCloud(object):
    def __init__(self, event):
        global aws_triggered
        aws_triggered = True

# In this set of tests we should only trigger HostScanEvent when remote or cidr are set
@handler.subscribe(HostScanEvent)
class testHostDiscovery(object):
    def __init__(self, event):
        assert config.remote is not None or config.cidr is not None
        assert config.remote == "1.2.3.4" or config.cidr == "1.2.3.4/24"

@handler.subscribe(NewHostEvent)
class testNewHostEvent(object):
    def __init__(self, event):
        if event.cloud == CloudTypes.AKS:
            global azure_triggered
            azure_triggered = True
            assert not str(event.host).startswith("3.4.5")

# Test that we only report this event for Azure hosts
@handler.subscribe(AzureMetadataApi)
class testAzureMetadataApi(object):
    def __init__(self, event):
        assert config.azure
