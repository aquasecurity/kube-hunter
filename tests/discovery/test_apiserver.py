# flake8: noqa: E402
import requests_mock
import time

from kube_hunter.conf import Config, set_config

set_config(Config())

from kube_hunter.modules.discovery.apiserver import ApiServer, ApiServiceDiscovery
from kube_hunter.core.events.types import Event
from kube_hunter.core.events import handler

counter = 0


def test_ApiServer():
    global counter
    counter = 0
    with requests_mock.Mocker() as m:
        m.get("https://mockOther:443", text="elephant")
        m.get("https://mockKubernetes:443", text='{"code":403}', status_code=403)
        m.get(
            "https://mockKubernetes:443/version",
            text='{"major": "1.14.10"}',
            status_code=200,
        )

        e = Event()
        e.protocol = "https"
        e.port = 443
        e.host = "mockOther"

        a = ApiServiceDiscovery(e)
        a.execute()

        e.host = "mockKubernetes"
        a.execute()

    # Allow the events to be processed. Only the one to mockKubernetes should trigger an event
    time.sleep(1)
    assert counter == 1


def test_ApiServerWithServiceAccountToken():
    global counter
    counter = 0
    with requests_mock.Mocker() as m:
        m.get(
            "https://mockKubernetes:443",
            request_headers={"Authorization": "Bearer very_secret"},
            text='{"code":200}',
        )
        m.get("https://mockKubernetes:443", text='{"code":403}', status_code=403)
        m.get(
            "https://mockKubernetes:443/version",
            text='{"major": "1.14.10"}',
            status_code=200,
        )
        m.get("https://mockOther:443", text="elephant")

        e = Event()
        e.protocol = "https"
        e.port = 443

        # We should discover an API Server regardless of whether we have a token
        e.host = "mockKubernetes"
        a = ApiServiceDiscovery(e)
        a.execute()
        time.sleep(0.1)
        assert counter == 1

        e.auth_token = "very_secret"
        a = ApiServiceDiscovery(e)
        a.execute()
        time.sleep(0.1)
        assert counter == 2

        # But we shouldn't generate an event if we don't see an error code or find the 'major' in /version
        e.host = "mockOther"
        a = ApiServiceDiscovery(e)
        a.execute()
        time.sleep(0.1)
        assert counter == 2


def test_InsecureApiServer():
    global counter
    counter = 0
    with requests_mock.Mocker() as m:
        m.get("http://mockOther:8080", text="elephant")
        m.get(
            "http://mockKubernetes:8080",
            text="""{
  "paths": [
    "/api",
    "/api/v1",
    "/apis",
    "/apis/",
    "/apis/admissionregistration.k8s.io",
    "/apis/admissionregistration.k8s.io/v1beta1",
    "/apis/apiextensions.k8s.io"
  ]}""",
        )

        m.get("http://mockKubernetes:8080/version", text='{"major": "1.14.10"}')
        m.get("http://mockOther:8080/version", status_code=404)

        e = Event()
        e.protocol = "http"
        e.port = 8080
        e.host = "mockOther"

        a = ApiServiceDiscovery(e)
        a.execute()

        e.host = "mockKubernetes"
        a.execute()

    # Allow the events to be processed. Only the one to mockKubernetes should trigger an event
    time.sleep(0.1)
    assert counter == 1


# We should only generate an ApiServer event for a response that looks like it came from a Kubernetes node
@handler.subscribe(ApiServer)
class testApiServer:
    def __init__(self, event):
        print("Event")
        assert event.host == "mockKubernetes"
        global counter
        counter += 1
