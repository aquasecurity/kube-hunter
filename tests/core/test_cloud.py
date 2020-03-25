import requests_mock
import json

from kube_hunter.core.events.types.common import NewHostEvent


# Testing if it doesn't try to run get_cloud if the cloud type is already set.
# get_cloud(1.2.3.4) will result with an error
def test_presetcloud():
    expcted = "AWS"
    hostEvent = NewHostEvent(host="1.2.3.4", cloud=expcted)
    assert expcted == hostEvent.cloud


# Test if we can dynamic assign a cloud, without calling get_cloud
def test_dynamiccloud():
    expected = "Google Cloud"
    hostEvent = NewHostEvent(host="1.2.3.4")
    hostEvent.cloud = expected
    assert hostEvent.cloud == expected


def test_getcloud():
    fake_host = "1.2.3.4"
    expected_cloud = "Azure"
    result = {
        "cloud": expected_cloud,
        "regionId": "europenorth",
        "region":"North Europe",
        "location":"Ireland",
        "ipAddress": fake_host
    }
    
    with requests_mock.mock() as m:
        m.get(f'https://api.azurespeed.com/api/region?ipOrUrl={fake_host}',
              text=json.dumps(result))
        hostEvent = NewHostEvent(host=fake_host)
        assert hostEvent.cloud == expected_cloud
    