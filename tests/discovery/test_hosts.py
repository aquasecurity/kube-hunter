import requests_mock
import time
from queue import Empty

from src.modules.discovery.aks import AzureHostDiscovery, AzureMetadataApi
from src.modules.discovery.hosts import HostScanEvent, RunningPodOnCloud
from src.core.events.types import Event, NewHostEvent
from src.core.events import handler
from src.core.types import CloudTypes

from __main__ import config

def test_AzureHostDiscovery():

    with requests_mock.Mocker() as m:
        e = RunningPodOnCloud(cloud=CloudTypes.AKS)

        config.azure = False
        config.remote = None
        config.cidr = None
        m.get("http://169.254.169.254/metadata/instance?api-version=2017-08-01", status_code=404)
        f = AzureHostDiscovery(e)
        assert not f.is_azure_api()

        # Test that we generate NewHostEvent for the addresses reported by the Azure Metadata API
        config.azure = True
        m.get("http://169.254.169.254/metadata/instance?api-version=2017-08-01", \
            text='{"network":{"interface":[{"ipv4":{"subnet":[{"address": "3.4.5.6", "prefix": "255.255.255.252"}]}}]}}')
        assert f.is_azure_api()
        f.execute()



# In this set of tests we should only trigger HostScanEvent when remote or cidr are set
@handler.subscribe(HostScanEvent)
class testHostDiscovery(object):
    def __init__(self, event):
        assert config.remote is not None or config.cidr is not None
        assert config.remote == "1.2.3.4" or config.cidr == "1.2.3.4/24"
        
# In this set of tests we should only get as far as finding a host if it's Azure
# because we're not running the code that would normally be triggered by a HostScanEvent
@handler.subscribe(NewHostEvent)
class testHostDiscoveryEvent(object):
    def __init__(self, event):
        assert config.azure
        assert str(event.host).startswith("3.4.5.")
        assert config.remote is None 
        assert config.cidr is None

# Test that we only report this event for Azure hosts
@handler.subscribe(AzureMetadataApi)
class testAzureMetadataApi(object):
    def __init__(self, event):
        assert config.azure
