import requests_mock
import time
from queue import Empty

from kube_hunter.modules.discovery.hosts import FromPodHostDiscovery, RunningAsPodEvent, HostScanEvent, AzureMetadataApi
from kube_hunter.core.events.types import Event, NewHostEvent
from kube_hunter.core.events import handler
from kube_hunter.conf import config

def test_FromPodHostDiscovery():

    with requests_mock.Mocker() as m:
        e = RunningAsPodEvent()

        config.azure = False
        config.remote = None
        config.cidr = None
        m.get("http://169.254.169.254/metadata/instance?api-version=2017-08-01", status_code=404)
        f = FromPodHostDiscovery(e)
        assert not f.is_azure_pod()
        # TODO For now we don't test the traceroute discovery version
        # f.execute()

        # Test that we generate NewHostEvent for the addresses reported by the Azure Metadata API
        config.azure = True
        m.get("http://169.254.169.254/metadata/instance?api-version=2017-08-01", \
            text='{"network":{"interface":[{"ipv4":{"subnet":[{"address": "3.4.5.6", "prefix": "255.255.255.252"}]}}]}}')
        assert f.is_azure_pod()
        f.execute()

        # Test that we don't trigger a HostScanEvent unless either config.remote or config.cidr are configured
        config.remote = "1.2.3.4"
        f.execute()

        config.azure = False
        config.remote = None 
        config.cidr = "1.2.3.4/24"
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
