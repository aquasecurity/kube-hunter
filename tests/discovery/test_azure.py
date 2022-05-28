import json
import time
import requests_mock

from kube_hunter.core.events.event_handler import handler
from kube_hunter.modules.discovery.hosts import RunningAsPodEvent
from kube_hunter.modules.discovery.cloud.azure import (
    AzureInstanceMetadataServiceDiscovery,
    AzureMetadataApiExposed,
    AzureSubnetsDiscovery,
)

event_counter = 0


def test_TestAzureMetadataApi():
    global event_counter

    f = AzureInstanceMetadataServiceDiscovery(RunningAsPodEvent())

    with requests_mock.Mocker() as m:
        m.get("http://169.254.169.254/metadata/versions", status_code=404)
        f.execute()

    # We expect 0 triggers.because versions returned 404
    time.sleep(0.01)
    assert event_counter == 0
    event_counter = 0

    with requests_mock.Mocker() as m:
        m.get("http://169.254.169.254/metadata/versions", text=AzureApiResponses.make_versions_response())
        m.get(
            "http://169.254.169.254/metadata/instance?api-version=2017-08-01",
            text=AzureApiResponses.make_instance_response([("192.168.1.0", "24")]),
        )
        f.execute()

    # Expect 1 trigger
    time.sleep(0.01)
    assert event_counter == 1
    event_counter = 0

    # Test subnet extraction:
    versions_info = {"2017-08-01": AzureApiResponses.make_instance_response([("192.168.0.0", "24")], raw=False)}
    asd = AzureSubnetsDiscovery(AzureMetadataApiExposed(versions_info))
    assert asd.extract_azure_subnet() == "192.168.0.0/24"


class AzureApiResponses:
    @staticmethod
    def make_instance_response(subnets, raw=True):
        response = {
            "network": {
                "interface": [
                    {"ipv4": {"subnet": [{"address": address, "prefix": prefix} for address, prefix in subnets]}}
                ]
            }
        }

        if raw:
            response = json.dumps(response)
        return response

    @staticmethod
    def make_versions_response():
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
