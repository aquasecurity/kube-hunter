# flake8: noqa: E402
from kube_hunter.core.types.vulnerabilities import AccessK8sApiServerTechnique
import requests_mock
import time

from kube_hunter.conf import Config, set_config

set_config(Config())

from kube_hunter.modules.hunting.apiserver import (
    AccessApiServer,
    AccessApiServerWithToken,
    ServerApiAccess,
    AccessApiServerActive,
)
from kube_hunter.modules.hunting.apiserver import (
    ListNamespaces,
    ListPodsAndNamespaces,
    ListRoles,
    ListClusterRoles,
)
from kube_hunter.modules.hunting.apiserver import ApiServerPassiveHunterFinished
from kube_hunter.modules.hunting.apiserver import CreateANamespace, DeleteANamespace
from kube_hunter.modules.discovery.apiserver import ApiServer
from kube_hunter.core.types import ExposedSensitiveInterfacesTechnique, AccessK8sApiServerTechnique
from kube_hunter.core.events.event_handler import handler

counter = 0


def test_ApiServerToken():
    global counter
    counter = 0

    e = ApiServer()
    e.host = "1.2.3.4"
    e.auth_token = "my-secret-token"

    # Test that the pod's token is passed on through the event
    h = AccessApiServerWithToken(e)
    assert h.event.auth_token == "my-secret-token"

    # This test doesn't generate any events
    time.sleep(0.01)
    assert counter == 0


def test_AccessApiServer():
    global counter
    counter = 0

    e = ApiServer()
    e.host = "mockKubernetes"
    e.port = 443
    e.protocol = "https"

    with requests_mock.Mocker() as m:
        m.get("https://mockKubernetes:443/api", text="{}")
        m.get(
            "https://mockKubernetes:443/api/v1/namespaces",
            text='{"items":[{"metadata":{"name":"hello"}}]}',
        )
        m.get(
            "https://mockKubernetes:443/api/v1/pods",
            text='{"items":[{"metadata":{"name":"podA", "namespace":"namespaceA"}}, \
                            {"metadata":{"name":"podB", "namespace":"namespaceB"}}]}',
        )
        m.get(
            "https://mockkubernetes:443/apis/rbac.authorization.k8s.io/v1/roles",
            status_code=403,
        )
        m.get(
            "https://mockkubernetes:443/apis/rbac.authorization.k8s.io/v1/clusterroles",
            text='{"items":[]}',
        )
        m.get(
            "https://mockkubernetes:443/version",
            text='{"major": "1","minor": "13+", "gitVersion": "v1.13.6-gke.13", \
                   "gitCommit": "fcbc1d20b6bca1936c0317743055ac75aef608ce", \
                   "gitTreeState": "clean", "buildDate": "2019-06-19T20:50:07Z", \
                   "goVersion": "go1.11.5b4", "compiler": "gc", \
                   "platform": "linux/amd64"}',
        )

        h = AccessApiServer(e)
        h.execute()

        # We should see events for Server API Access, Namespaces, Pods, and the passive hunter finished
        time.sleep(0.01)
        assert counter == 4

    # Try with an auth token
    counter = 0
    with requests_mock.Mocker() as m:
        # TODO check that these responses reflect what Kubernetes does
        m.get("https://mocktoken:443/api", text="{}")
        m.get(
            "https://mocktoken:443/api/v1/namespaces",
            text='{"items":[{"metadata":{"name":"hello"}}]}',
        )
        m.get(
            "https://mocktoken:443/api/v1/pods",
            text='{"items":[{"metadata":{"name":"podA", "namespace":"namespaceA"}}, \
                            {"metadata":{"name":"podB", "namespace":"namespaceB"}}]}',
        )
        m.get(
            "https://mocktoken:443/apis/rbac.authorization.k8s.io/v1/roles",
            status_code=403,
        )
        m.get(
            "https://mocktoken:443/apis/rbac.authorization.k8s.io/v1/clusterroles",
            text='{"items":[{"metadata":{"name":"my-role"}}]}',
        )

        e.auth_token = "so-secret"
        e.host = "mocktoken"
        h = AccessApiServerWithToken(e)
        h.execute()

        # We should see the same set of events but with the addition of Cluster Roles
        time.sleep(0.01)
        assert counter == 5


@handler.subscribe(ListNamespaces)
class test_ListNamespaces:
    def __init__(self, event):
        print("ListNamespaces")
        assert event.evidence == ["hello"]
        if event.host == "mocktoken":
            assert event.auth_token == "so-secret"
        else:
            assert event.auth_token is None
        global counter
        counter += 1


@handler.subscribe(ListPodsAndNamespaces)
class test_ListPodsAndNamespaces:
    def __init__(self, event):
        print("ListPodsAndNamespaces")
        assert len(event.evidence) == 2
        for pod in event.evidence:
            if pod["name"] == "podA":
                assert pod["namespace"] == "namespaceA"
            if pod["name"] == "podB":
                assert pod["namespace"] == "namespaceB"
        if event.host == "mocktoken":
            assert event.auth_token == "so-secret"
            assert "token" in event.name
            assert "anon" not in event.name
        else:
            assert event.auth_token is None
            assert "token" not in event.name
            assert "anon" in event.name
        global counter
        counter += 1


# Should never see this because the API call in the test returns 403 status code
@handler.subscribe(ListRoles)
class test_ListRoles:
    def __init__(self, event):
        print("ListRoles")
        assert 0
        global counter
        counter += 1


# Should only see this when we have a token because the API call returns an empty list of items
# in the test where we have no token
@handler.subscribe(ListClusterRoles)
class test_ListClusterRoles:
    def __init__(self, event):
        print("ListClusterRoles")
        assert event.auth_token == "so-secret"
        global counter
        counter += 1


@handler.subscribe(ServerApiAccess)
class test_ServerApiAccess:
    def __init__(self, event):
        print("ServerApiAccess")
        if event.category == ExposedSensitiveInterfacesTechnique:
            assert event.auth_token is None
        else:
            assert event.category == AccessK8sApiServerTechnique
            assert event.auth_token == "so-secret"
        global counter
        counter += 1


@handler.subscribe(ApiServerPassiveHunterFinished)
class test_PassiveHunterFinished:
    def __init__(self, event):
        print("PassiveHunterFinished")
        assert event.namespaces == ["hello"]
        global counter
        counter += 1


def test_AccessApiServerActive():
    e = ApiServerPassiveHunterFinished(namespaces=["hello-namespace"])
    e.host = "mockKubernetes"
    e.port = 443
    e.protocol = "https"

    with requests_mock.Mocker() as m:
        # TODO more tests here with real responses
        m.post(
            "https://mockKubernetes:443/api/v1/namespaces",
            text="""
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
""",
        )
        m.post("https://mockKubernetes:443/api/v1/clusterroles", text="{}")
        m.post(
            "https://mockkubernetes:443/apis/rbac.authorization.k8s.io/v1/clusterroles",
            text="{}",
        )
        m.post(
            "https://mockkubernetes:443/api/v1/namespaces/hello-namespace/pods",
            text="{}",
        )
        m.post(
            "https://mockkubernetes:443" "/apis/rbac.authorization.k8s.io/v1/namespaces/hello-namespace/roles",
            text="{}",
        )

        m.delete(
            "https://mockKubernetes:443/api/v1/namespaces/abcde",
            text="""
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
        """,
        )

        h = AccessApiServerActive(e)
        h.execute()


@handler.subscribe(CreateANamespace)
class test_CreateANamespace:
    def __init__(self, event):
        assert "abcde" in event.evidence


@handler.subscribe(DeleteANamespace)
class test_DeleteANamespace:
    def __init__(self, event):
        assert "2019-02-26" in event.evidence
