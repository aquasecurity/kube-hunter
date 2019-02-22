import requests_mock

from apiserver import AccessApiServerViaServiceAccountToken
from ..discovery.apiserver import ApiServer
from ...core.events.types import Event
from ...core.events import handler

def test_ApiServer():

    e = ApiServer()
    e.host = "1.2.3.4"
    e.auth_token = "my-secret-token"

    # Test that the pod's token is passed on through the event
    h = AccessApiServerViaServiceAccountToken(e)
    assert h.event.auth_token == "my-secret-token"