import json
import requests
import requests_mock

from kube_hunter.conf import Config, set_config
from kube_hunter.core.events import K8sVersionDisclosure, NewHostEvent, OpenPortEvent

set_config(Config())


class TestNewHostEvent:
    def test_cloud_preset(self):
        """ Testing if it doesn't try to run get_cloud if the cloud type is already set.
        get_cloud(1.2.3.4) will result with an error
        """
        expcted = "TestCloud"
        actual = NewHostEvent(host="1.2.3.4", cloud=expcted).cloud

        assert expcted == actual

    def test_cloud_successful(self):
        fake_host = "1.2.3.4"
        expected = "Azure"
        fake_result = {"cloud": expected}

        with requests_mock.mock() as m:
            m.get(f"https://api.azurespeed.com/api/region?ipOrUrl={fake_host}", text=json.dumps(fake_result))
            actual = NewHostEvent(host=fake_host).cloud

        assert expected == actual

    def test_get_cloud_connection_error(self):
        expected = "NoCloud"
        fake_host = "1.2.3.4"

        with requests_mock.mock() as m:
            m.get(f"https://api.azurespeed.com/api/region?ipOrUrl={fake_host}", exc=requests.ConnectionError())
            actual = NewHostEvent(host=fake_host).get_cloud()

        assert expected == actual

    def test_get_cloud_exception(self):
        expected = "NoCloud"
        fake_host = "1.2.3.4"

        with requests_mock.mock() as m:
            m.get(f"https://api.azurespeed.com/api/region?ipOrUrl={fake_host}", exc=Exception())
            actual = NewHostEvent(host=fake_host).get_cloud()

        assert expected == actual

    def test_str(self):
        expected = "1.2.3.4"
        event = NewHostEvent(expected)
        actual = str(event)

        assert expected == actual

    def test_location(self):
        expected = "1.2.3.4"
        event = NewHostEvent(expected)
        actual = event.location()

        assert expected == actual


class TestOpenPortEvent:
    def test_str(self):
        expected = "1.2.3.4:1234"
        event = OpenPortEvent("1.2.3.4", 1234)
        actual = str(event)

        assert expected == actual

    def test_location(self):
        expected = "1.2.3.4:1234"
        event = OpenPortEvent("1.2.3.4", 1234)
        actual = event.location()

        assert expected == actual


class TestK8sVersionDisclosure:
    def test_explain(self):
        expected = f"The kubernetes version could be obtained from the /version endpoint and it was easy"
        actual = K8sVersionDisclosure("1.0", "/version", "and it was easy").explain()

        assert expected == actual
