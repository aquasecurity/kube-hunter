# from mock import patch
import requests_mock

from apiserver import ApiServer, ApiServerDiscovery
from ...core.events.types import Event
from ...core.events import handler

def test_ApiServer():

    with requests_mock.Mocker() as m:
        m.get('https://mockOther:443', text='elephant')
        m.get('https://mockKubernetes:443', text='code')

        e = Event()
        e.port = 443
        e.host = 'mockOther'

        a = ApiServerDiscovery(e)
        a.execute()
        
        e.host = 'mockKubernetes'
        a.execute()

# We should only generate an ApiServer event for a response that looks like it came from a Kubernetes node
@handler.subscribe(ApiServer)
class testApiServer(object):
    def __init__(self, event):
        assert event.host == 'mockKubernetes'
