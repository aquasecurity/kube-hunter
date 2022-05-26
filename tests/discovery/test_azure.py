import json
import time
import requests_mock

from kube_hunter.core.events.event_handler import handler
from kube_hunter.modules.discovery.hosts import RunningAsPodEvent
from kube_hunter.modules.discovery.cloud.azure import (
    AzureInstanceMetadataServiceDiscovery, 
    AzureMetadataApiExposed
)

event_counter = 0


def test_TestAzureMetadataApi():
    global event_counter

    f = AzureInstanceMetadataServiceDiscovery(RunningAsPodEvent())

    with requests_mock.Mocker() as m:
        m.get("http://169.254.169.254/metadata/versions/", status_code=404)
        f.execute()
    
    # We expect 0 triggers.because versions returned 404 
    time.sleep(0.01)
    assert event_counter == 0
    event_counter = 0

    with requests_mock.Mocker() as m:
        m.get("http://169.254.169.254/metadata/versions/", text=TestAzureMetadataApiDiscovery.make_versions_response())
        m.get("http://169.254.169.254/metadata/instance?api-version=2017-08-01", text=TestAzureMetadataApiDiscovery.make_versions_response())
        f.execute()
    

    # Expect 1 trigger
    time.sleep(0.01)
    assert event_counter == 1
    event_counter = 0


class TestAzureMetadataApiDiscovery:
    @staticmethod
    def make_instance_response() -> str:
        return json.dumps(
            {
                "network": {
                    "interface": [
                        {"ipv4": {"subnet": [{"address": address, "prefix": prefix} for address, prefix in subnets]}}
                    ]
                }
            }
        )
    
    @staticmethod
    def make_versions_response() -> str:
        return json.dumps(
            {
                "apiVersions": [
                    "2017-08-01",
                ]
            }
        )


@handler.subscribe(AzureMetadataApiExposed)
class TestAzureMetadataApiExposed:
    def __init__(self, event):
        global event_counter
        event_counter += 1

