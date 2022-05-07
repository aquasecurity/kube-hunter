# flake8: noqa: E402
import requests_mock
import json

from kube_hunter.conf import Config, set_config

set_config(Config())

from kube_hunter.core.events.types import NewHostEvent


def test_presetcloud():
    """Testing if it doesn't try to run get_cloud if the cloud type is already set.
    get_cloud(1.2.3.4) will result with an error
    """
    expcted = "AWS"
    hostEvent = NewHostEvent(host="1.2.3.4", cloud=expcted)
    assert expcted == hostEvent.cloud


def test_getcloud():
    fake_host = "1.2.3.4"
    expected_cloud = "Azure"
    result = {"cloud": expected_cloud}

    with requests_mock.mock() as m:
        m.get(f"https://api.azurespeed.com/api/region?ipOrUrl={fake_host}", text=json.dumps(result))
        hostEvent = NewHostEvent(host=fake_host)
        assert hostEvent.cloud == expected_cloud
