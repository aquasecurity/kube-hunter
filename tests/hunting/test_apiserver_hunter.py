import requests_mock

from src.modules.hunting.apiserver import AccessApiServer, AccessApiServerWithToken, ServerApiAccess, AccessApiServerActive
from src.modules.hunting.apiserver import ListAllNamespaces, ListPodsAndNamespaces, ListAllRoles, ListAllClusterRoles
from src.modules.hunting.apiserver import ApiServerPassiveHunterFinished
from src.modules.hunting.apiserver import CreateANamespace, DeleteANamespace
from src.modules.discovery.apiserver import ApiServer
from src.core.events.types import Event
from src.core.types import UnauthenticatedAccess, InformationDisclosure
from src.core.events import handler

def test_ApiServerToken():

    e = ApiServer()
    e.host = "1.2.3.4"
    e.auth_token = "my-secret-token"

    # Test that the pod's token is passed on through the event
    h = AccessApiServerWithToken(e)
    assert h.event.auth_token == "my-secret-token"

def test_AccessApiServer():
    e = ApiServer()
    e.host = "mockKubernetes"
    e.port = 443

    with requests_mock.Mocker() as m:
        # TODO check that these responses reflect what Kubernetes does
        m.get('https://mockKubernetes:443/api', text='{}')
        m.get('https://mockKubernetes:443/api/v1/namespaces', text='{"items":[{"metadata":{"name":"hello"}}]}')
        m.get('https://mockKubernetes:443/api/v1/pods', 
            text='{"items":[{"metadata":{"name":"podA", "namespace":"namespaceA"}}, \
                            {"metadata":{"name":"podB", "namespace":"namespaceB"}}]}')
        m.get('https://mockkubernetes:443/apis/rbac.authorization.k8s.io/v1/roles', status_code=403)
        m.get('https://mockkubernetes:443/apis/rbac.authorization.k8s.io/v1/clusterroles', text='{"items":[]}')

        h = AccessApiServer(e)
        h.execute()

    with requests_mock.Mocker() as m:
        # TODO check that these responses reflect what Kubernetes does
        m.get('https://mockKubernetesToken:443/api', text='{}')
        m.get('https://mockKubernetesToken:443/api/v1/namespaces', text='{"items":[{"metadata":{"name":"hello"}}]}')
        m.get('https://mockKubernetesToken:443/api/v1/pods', 
            text='{"items":[{"metadata":{"name":"podA", "namespace":"namespaceA"}}, \
                            {"metadata":{"name":"podB", "namespace":"namespaceB"}}]}')
        m.get('https://mockkubernetesToken:443/apis/rbac.authorization.k8s.io/v1/roles', status_code=403)
        m.get('https://mockkubernetesToken:443/apis/rbac.authorization.k8s.io/v1/clusterroles', 
            text='{"items":[{"metadata":{"name":"my-role"}}]}')

        e.auth_token = "so-secret"
        e.host = "mockKubernetesToken"
        h = AccessApiServerWithToken(e)
        h.execute()


@handler.subscribe(ListAllNamespaces)
class test_ListAllNamespaces(object):
    def __init__(self, event):
        assert event.evidence == ['hello']
        if event.host == "mockKubernetesToken":
            assert event.auth_token == "so-secret"
        else:
            assert event.auth_token is None
        

@handler.subscribe(ListPodsAndNamespaces)
class test_ListPodsAndNamespaces(object):
    def __init__(self, event):
        assert len(event.evidence) == 2
        for pod in event.evidence:
            if pod["name"] == "podA":
                assert pod["namespace"] == "namespaceA"
            if pod["name"] == "podB":
                assert pod["namespace"] == "namespaceB"                
        if event.host == "mockKubernetesToken":
            assert event.auth_token == "so-secret"
        else:
            assert event.auth_token is None

# Should never see this because the API call in the test returns 403 status code
@handler.subscribe(ListAllRoles)
class test_ListAllRoles(object):
    def __init__(self, event):
        assert 0 

# Should only see this when we have a token because the API call returns an empty list of items
# in the test where we have no token
@handler.subscribe(ListAllClusterRoles)
class test_ListAllClusterRoles(object):
    def __init__(self, event):
        assert event.auth_token == "so-secret"

@handler.subscribe(ServerApiAccess)
class test_ServerApiAccess(object):
    def __init__(self, event):
        if event.category == UnauthenticatedAccess:
            assert event.auth_token is None
        else:
            assert event.category == InformationDisclosure
            assert event.auth_token is not None

@handler.subscribe(ApiServerPassiveHunterFinished)
class test_PassiveHunterFinished(object):
    def __init__(self, event):
        assert event.namespaces == ["hello"]

def test_AccessApiServerActive():
    e = ApiServerPassiveHunterFinished(namespaces=["hello-namespace"])
    e.host = "mockKubernetes"
    e.port = 443

    with requests_mock.Mocker() as m:
        # TODO check that these responses reflect what Kubernetes does
        m.post('https://mockKubernetes:443/api/v1/namespaces', text="""
{
  "kind": "Namespace",
  "apiVersion": "v1",
  "metadata": {
    "name": "abcde",
    "selfLink": "/api/v1/namespaces/abcde",
    "uid": "4a7aa47c-39ba-11e9-ab46-08002781145e",
    "resourceVersion": "694180",
    "creationTimestamp": "2019-02-26T11:33:08Z"
  },
  "spec": {
    "finalizers": [
      "kubernetes"
    ]
  },
  "status": {
    "phase": "Active"
  }
}
"""
)
        m.post('https://mockKubernetes:443/api/v1/clusterroles', text='{}')
        m.post('https://mockkubernetes:443/apis/rbac.authorization.k8s.io/v1/clusterroles', text='{}')
        m.post('https://mockkubernetes:443/api/v1/namespaces/hello-namespace/pods', text='{}')
        m.post('https://mockkubernetes:443/apis/rbac.authorization.k8s.io/v1/namespaces/hello-namespace/roles', text='{}')

        m.delete('https://mockKubernetes:443/api/v1/namespaces/abcde', text="""
{
  "kind": "Namespace",
  "apiVersion": "v1",
  "metadata": {
    "name": "abcde",
    "selfLink": "/api/v1/namespaces/abcde",
    "uid": "4a7aa47c-39ba-11e9-ab46-08002781145e",
    "resourceVersion": "694780",
    "creationTimestamp": "2019-02-26T11:33:08Z",
    "deletionTimestamp": "2019-02-26T11:40:58Z"
  },
  "spec": {
    "finalizers": [
      "kubernetes"
    ]
  },
  "status": {
    "phase": "Terminating"
  }
}        
        """)

        h = AccessApiServerActive(e)
        h.execute()

@handler.subscribe(CreateANamespace)
class test_CreateANamespace(object):
    def __init__(self, event):
        assert "abcde" in event.evidence

@handler.subscribe(DeleteANamespace)
class test_DeleteANamespace(object):
    def __init__(self, event):
        assert "2019-02-26" in event.evidence