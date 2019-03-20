import requests_mock
import time

from src.modules.discovery.apiserver import ApiServer, ApiServerDiscovery
from src.core.events.types import Event
from src.core.events import handler

counter = 0

def test_ApiServer():
    global counter 
    counter = 0
    with requests_mock.Mocker() as m:
        m.get('https://mockOther:443', text='elephant')
        m.get('https://mockKubernetes:443', text='{"code":403}')

        e = Event()
        e.port = 443
        e.host = 'mockOther'

        a = ApiServerDiscovery(e)
        a.execute()
        
        e.host = 'mockKubernetes'
        a.execute()

    # Allow the events to be processed. Only the one to mockKubernetes should trigger an event
    time.sleep(0.1)
    assert counter == 1

def test_ApiServerWithServiceAccountToken():
    global counter
    counter = 0
    with requests_mock.Mocker() as m:
        m.get('https://mockKubernetes:443', request_headers={'Authorization':'Bearer very_secret'}, text='{"code":200}')
        m.get('https://mockKubernetes:443', text='{"code":403}')
        m.get('https://mockOther:443', text='elephant')

        e = Event()
        e.port = 443

        # We should discover an API Server regardless of whether we have a token
        e.host = 'mockKubernetes'
        a = ApiServerDiscovery(e)
        a.execute()
        time.sleep(0.1)
        assert counter == 1

        e.auth_token = "very_secret"
        a = ApiServerDiscovery(e)
        a.execute()
        time.sleep(0.1)
        assert counter == 2

        # But we shouldn't generate an event if we don't see an error code
        e.host = 'mockOther'
        a = ApiServerDiscovery(e)
        a.execute()
        time.sleep(0.1)
        assert counter == 2


# We should only generate an ApiServer event for a response that looks like it came from a Kubernetes node
@handler.subscribe(ApiServer)
class testApiServer(object):
    def __init__(self, event):
        assert event.host == 'mockKubernetes'
        global counter
        counter += 1