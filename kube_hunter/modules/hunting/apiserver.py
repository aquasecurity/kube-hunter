import logging
import json
import uuid
import requests

from kube_hunter.conf import get_config
from kube_hunter.modules.discovery.apiserver import ApiServer
from kube_hunter.core.events import K8sVersionDisclosure
from kube_hunter.core.pubsub.subscription import Event, subscribe
from kube_hunter.core.types import (
    AccessRisk,
    ActiveHunter,
    Hunter,
    InformationDisclosure,
    KubernetesCluster,
    UnauthenticatedAccess,
    Vulnerability,
)

logger = logging.getLogger(__name__)


class ServerApiAccess(Vulnerability):
    """The API Server port is accessible.
    Depending on your RBAC settings this could expose access to or control of your cluster."""

    def __init__(self, evidence: str, using_token: bool):
        if using_token:
            name = "Access to API using service account token"
            category = InformationDisclosure
        else:
            name = "Unauthenticated access to API"
            category = UnauthenticatedAccess
        super().__init__(name=name, component=KubernetesCluster, category=category, vid="KHV005", evidence=evidence)


class ServerApiHTTPAccess(Vulnerability):
    """The API Server port is accessible over HTTP, and therefore unencrypted.
    Depending on your RBAC settings this could expose access to or control of your cluster."""

    def __init__(self, evidence):
        super().__init__(
            name="Insecure (HTTP) access to API",
            component=KubernetesCluster,
            category=UnauthenticatedAccess,
            vid="KHV006",
            evidence=evidence,
        )


class ApiInfoDisclosure(Vulnerability):
    def __init__(self, evidence, using_token, name):
        if using_token:
            name += " using service account token"
        else:
            name += " as anonymous user"
        super().__init__(
            name=name, component=KubernetesCluster, category=InformationDisclosure, vid="KHV007", evidence=evidence
        )


class ListPodsAndNamespaces(ApiInfoDisclosure):
    """ Accessing pods might give an attacker valuable information"""

    def __init__(self, evidence, using_token):
        super().__init__(evidence, using_token, "Listing pods")


class ListNamespaces(ApiInfoDisclosure):
    """ Accessing namespaces might give an attacker valuable information """

    def __init__(self, evidence, using_token):
        super().__init__(evidence, using_token, "Listing namespaces")


class ListRoles(ApiInfoDisclosure):
    """ Accessing roles might give an attacker valuable information """

    def __init__(self, evidence, using_token):
        super().__init__(evidence, using_token, "Listing roles")


class ListClusterRoles(ApiInfoDisclosure):
    """ Accessing cluster roles might give an attacker valuable information """

    def __init__(self, evidence, using_token):
        super().__init__(evidence, using_token, "Listing cluster roles")


class CreateANamespace(Vulnerability):
    """ Creating a namespace might give an attacker an area with default (exploitable) permissions to run pods in """

    def __init__(self, evidence):
        super().__init__(
            name="Created a namespace", component=KubernetesCluster, category=AccessRisk, evidence=evidence
        )


class DeleteANamespace(Vulnerability):
    """ Deleting a namespace might give an attacker the option to affect application behavior """

    def __init__(self, evidence):
        super().__init__(name="Delete a namespace", component=KubernetesCluster, category=AccessRisk, evidence=evidence)


class CreateARole(Vulnerability):
    """ Creating a role might give an attacker the option to harm the normal behavior of newly created pods
    within the specified namespaces.
    """

    def __init__(self, evidence):
        super().__init__(name="Created a role", component=KubernetesCluster, category=AccessRisk, evidence=evidence)


class CreateAClusterRole(Vulnerability):
    """ Creating a cluster role might give an attacker the option to harm the normal behavior of newly created pods
    across the whole cluster
    """

    def __init__(self, evidence):
        super().__init__(
            name="Created a cluster role", component=KubernetesCluster, category=AccessRisk, evidence=evidence
        )


class PatchARole(Vulnerability):
    """ Patching a role might give an attacker the option to create new pods with custom roles within the
    specific role's namespace scope
    """

    def __init__(self, evidence):
        super().__init__(name="Patched a role", component=KubernetesCluster, category=AccessRisk, evidence=evidence)


class PatchAClusterRole(Vulnerability):
    """ Patching a cluster role might give an attacker the option to create new pods with custom roles within the whole
    cluster scope.
    """

    def __init__(self, evidence):
        super().__init__(
            name="Patched a cluster role", component=KubernetesCluster, category=AccessRisk, evidence=evidence
        )


class DeleteARole(Vulnerability):
    """ Deleting a role might allow an attacker to affect access to resources in the namespace"""

    def __init__(self, evidence):
        super().__init__(name="Deleted a role", component=KubernetesCluster, category=AccessRisk, evidence=evidence)


class DeleteAClusterRole(Vulnerability):
    """ Deleting a cluster role might allow an attacker to affect access to resources in the cluster"""

    def __init__(self, evidence):
        super().__init__(
            name="Deleted a cluster role", component=KubernetesCluster, category=AccessRisk, evidence=evidence
        )


class CreateAPod(Vulnerability):
    """ Creating a new pod allows an attacker to run custom code"""

    def __init__(self, evidence):
        super().__init__(name="Created A Pod", component=KubernetesCluster, category=AccessRisk, evidence=evidence)


class CreateAPrivilegedPod(Vulnerability):
    """ Creating a new PRIVILEGED pod would gain an attacker FULL CONTROL over the cluster"""

    def __init__(self, evidence):
        super().__init__(
            name="Created A PRIVILEGED Pod", component=KubernetesCluster, category=AccessRisk, evidence=evidence
        )


class PatchAPod(Vulnerability):
    """ Patching a pod allows an attacker to compromise and control it """

    def __init__(self, evidence):
        super().__init__(name="Patched A Pod", component=KubernetesCluster, category=AccessRisk, evidence=evidence)


class DeleteAPod(Vulnerability):
    """ Deleting a pod allows an attacker to disturb applications on the cluster """

    def __init__(self, evidence):
        super().__init__(name="Deleted A Pod", component=KubernetesCluster, category=AccessRisk, evidence=evidence)


class ApiServerPassiveHunterFinished(Event):
    def __init__(self, namespaces):
        super().__init__()
        self.namespaces = namespaces


# This Hunter checks what happens if we try to access the API Server without a service account token
# If we have a service account token we'll also trigger AccessApiServerWithToken below
@subscribe(ApiServer)
class AccessApiServer(Hunter):
    """ API Server Hunter
    Checks if API server is accessible
    """

    def __init__(self, event):
        super().__init__(event)
        self.path = f"{self.event.protocol}://{self.event.host}:{self.event.port}"
        self.headers = {}
        self.with_token = False

    def access_api_server(self):
        config = get_config()
        logger.debug(f"Passive Hunter is attempting to access the API at {self.path}")
        try:
            r = requests.get(f"{self.path}/api", headers=self.headers, verify=False, timeout=config.network_timeout)
            if r.status_code == 200 and r.content:
                return r.content
        except requests.exceptions.ConnectionError:
            pass
        return False

    def get_items(self, path):
        config = get_config()
        try:
            items = []
            r = requests.get(path, headers=self.headers, verify=False, timeout=config.network_timeout)
            if r.status_code == 200:
                resp = json.loads(r.content)
                for item in resp["items"]:
                    items.append(item["metadata"]["name"])
                return items
            logger.debug(f"Got HTTP {r.status_code} respone: {r.text}")
        except (requests.exceptions.ConnectionError, KeyError):
            logger.debug(f"Failed retrieving items from API server at {path}")

        return None

    def get_pods(self, namespace=None):
        config = get_config()
        pods = []
        try:
            if not namespace:
                r = requests.get(
                    f"{self.path}/api/v1/pods", headers=self.headers, verify=False, timeout=config.network_timeout,
                )
            else:
                r = requests.get(
                    f"{self.path}/api/v1/namespaces/{namespace}/pods",
                    headers=self.headers,
                    verify=False,
                    timeout=config.network_timeout,
                )
            if r.status_code == 200:
                resp = json.loads(r.content)
                for item in resp["items"]:
                    name = item["metadata"]["name"].encode("ascii", "ignore")
                    namespace = item["metadata"]["namespace"].encode("ascii", "ignore")
                    pods.append({"name": name, "namespace": namespace})
                return pods
        except (requests.exceptions.ConnectionError, KeyError):
            pass
        return None

    def execute(self):
        api = self.access_api_server()
        if api:
            if self.event.protocol == "http":
                yield ServerApiHTTPAccess(api)
            else:
                yield ServerApiAccess(api, self.with_token)

        namespaces = self.get_items("{path}/api/v1/namespaces".format(path=self.path))
        if namespaces:
            yield ListNamespaces(namespaces, self.with_token)

        roles = self.get_items(f"{self.path}/apis/rbac.authorization.k8s.io/v1/roles")
        if roles:
            yield ListRoles(roles, self.with_token)

        cluster_roles = self.get_items(f"{self.path}/apis/rbac.authorization.k8s.io/v1/clusterroles")
        if cluster_roles:
            yield ListClusterRoles(cluster_roles, self.with_token)

        pods = self.get_pods()
        if pods:
            yield ListPodsAndNamespaces(pods, self.with_token)

        # If we have a service account token, this event should get triggered twice - once with and once without
        # the token
        yield ApiServerPassiveHunterFinished(namespaces)


@subscribe(ApiServer, predicate=lambda event: event.auth_token)
class AccessApiServerWithToken(AccessApiServer):
    """ API Server Hunter
    Accessing the API server using the service account token obtained from a compromised pod
    """

    def __init__(self, event):
        super().__init__(event)
        assert self.event.auth_token
        self.headers = {"Authorization": f"Bearer {self.event.auth_token}"}
        self.category = InformationDisclosure
        self.with_token = True


@subscribe(ApiServerPassiveHunterFinished)
class AccessApiServerActive(ActiveHunter):
    """API server hunter
    Accessing the api server might grant an attacker full control over the cluster
    """

    def __init__(self, event):
        super().__init__(event)
        self.path = f"{self.event.protocol}://{self.event.host}:{self.event.port}"

    def create_item(self, path, data):
        config = get_config()
        headers = {"Content-Type": "application/json"}
        if self.event.auth_token:
            headers["Authorization"] = f"Bearer {self.event.auth_token}"

        try:
            res = requests.post(path, verify=False, data=data, headers=headers, timeout=config.network_timeout)
            if res.status_code in [200, 201, 202]:
                parsed_content = res.json()
                return parsed_content["metadata"]["name"]
        except (requests.exceptions.ConnectionError, KeyError):
            pass
        return None

    def patch_item(self, path, data):
        config = get_config()
        headers = {"Content-Type": "application/json-patch+json"}
        if self.event.auth_token:
            headers["Authorization"] = f"Bearer {self.event.auth_token}"
        try:
            res = requests.patch(path, headers=headers, verify=False, data=data, timeout=config.network_timeout)
            if res.status_code not in [200, 201, 202]:
                return None
            parsed_content = res.json()
            # TODO is there a patch timestamp we could use?
            return parsed_content["metadata"]["namespace"]
        except (requests.exceptions.ConnectionError, KeyError):
            pass
        return None

    def delete_item(self, path):
        config = get_config()
        headers = {}
        if self.event.auth_token:
            headers["Authorization"] = f"Bearer {self.event.auth_token}"
        try:
            res = requests.delete(path, headers=headers, verify=False, timeout=config.network_timeout)
            if res.status_code in [200, 201, 202]:
                parsed_content = res.json()
                return parsed_content["metadata"]["deletionTimestamp"]
        except (requests.exceptions.ConnectionError, KeyError):
            pass
        return None

    def create_a_pod(self, namespace, is_privileged):
        privileged_value = {"securityContext": {"privileged": True}} if is_privileged else {}
        random_name = str(uuid.uuid4())[0:5]
        pod = {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": random_name},
            "spec": {
                "containers": [
                    {"name": random_name, "image": "nginx:1.7.9", "ports": [{"containerPort": 80}], **privileged_value}
                ]
            },
        }
        return self.create_item(path=f"{self.path}/api/v1/namespaces/{namespace}/pods", data=json.dumps(pod))

    def delete_a_pod(self, namespace, pod_name):
        delete_timestamp = self.delete_item(f"{self.path}/api/v1/namespaces/{namespace}/pods/{pod_name}")
        if not delete_timestamp:
            logger.error(f"Created pod {pod_name} in namespace {namespace} but unable to delete it")
        return delete_timestamp

    def patch_a_pod(self, namespace, pod_name):
        data = [{"op": "add", "path": "/hello", "value": ["world"]}]
        return self.patch_item(
            path=f"{self.path}/api/v1/namespaces/{namespace}/pods/{pod_name}", data=json.dumps(data),
        )

    def create_namespace(self):
        random_name = (str(uuid.uuid4()))[0:5]
        data = {
            "kind": "Namespace",
            "apiVersion": "v1",
            "metadata": {"name": random_name, "labels": {"name": random_name}},
        }
        return self.create_item(path=f"{self.path}/api/v1/namespaces", data=json.dumps(data))

    def delete_namespace(self, namespace):
        delete_timestamp = self.delete_item(f"{self.path}/api/v1/namespaces/{namespace}")
        if not delete_timestamp:
            logger.error(f"Created namespace {namespace} but failed to delete it")
        return delete_timestamp

    def create_a_role(self, namespace):
        name = str(uuid.uuid4())[0:5]
        role = {
            "kind": "Role",
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "metadata": {"namespace": namespace, "name": name},
            "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "watch", "list"]}],
        }
        return self.create_item(
            path=f"{self.path}/apis/rbac.authorization.k8s.io/v1/namespaces/{namespace}/roles", data=json.dumps(role),
        )

    def create_a_cluster_role(self):
        name = str(uuid.uuid4())[0:5]
        cluster_role = {
            "kind": "ClusterRole",
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "metadata": {"name": name},
            "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "watch", "list"]}],
        }
        return self.create_item(
            path=f"{self.path}/apis/rbac.authorization.k8s.io/v1/clusterroles", data=json.dumps(cluster_role),
        )

    def delete_a_role(self, namespace, name):
        delete_timestamp = self.delete_item(
            f"{self.path}/apis/rbac.authorization.k8s.io/v1/namespaces/{namespace}/roles/{name}"
        )
        if delete_timestamp is None:
            logger.error(f"Created role {name} in namespace {namespace} but unable to delete it")
        return delete_timestamp

    def delete_a_cluster_role(self, name):
        delete_timestamp = self.delete_item(f"{self.path}/apis/rbac.authorization.k8s.io/v1/clusterroles/{name}")
        if delete_timestamp is None:
            logger.error(f"Created cluster role {name} but unable to delete it")
        return delete_timestamp

    def patch_a_role(self, namespace, role):
        data = [{"op": "add", "path": "/hello", "value": ["world"]}]
        return self.patch_item(
            path=f"{self.path}/apis/rbac.authorization.k8s.io/v1/namespaces/{namespace}/roles/{role}",
            data=json.dumps(data),
        )

    def patch_a_cluster_role(self, cluster_role):
        data = [{"op": "add", "path": "/hello", "value": ["world"]}]
        return self.patch_item(
            path=f"{self.path}/apis/rbac.authorization.k8s.io/v1/clusterroles/{cluster_role}", data=json.dumps(data),
        )

    def execute(self):
        # Try creating cluster-wide objects
        namespace = self.create_namespace()
        if namespace:
            yield CreateANamespace(f"new namespace name: {namespace}")
            delete_timestamp = self.delete_namespace(namespace)
            if delete_timestamp:
                yield DeleteANamespace(delete_timestamp)

        cluster_role = self.create_a_cluster_role()
        if cluster_role:
            yield CreateAClusterRole(f"Cluster role name: {cluster_role}")

            patch_evidence = self.patch_a_cluster_role(cluster_role)
            if patch_evidence:
                yield PatchAClusterRole(f"Patched Cluster Role Name: {cluster_role}  Patch evidence: {patch_evidence}")

            delete_timestamp = self.delete_a_cluster_role(cluster_role)
            if delete_timestamp:
                yield DeleteAClusterRole(f"Cluster role {cluster_role} deletion time {delete_timestamp}")

        #  Try attacking all the namespaces we know about
        if self.event.namespaces:
            for namespace in self.event.namespaces:
                # Try creating and deleting a privileged pod
                pod_name = self.create_a_pod(namespace, True)
                if pod_name:
                    yield CreateAPrivilegedPod(f"Pod Name: {pod_name} Namespace: {namespace}")
                    delete_time = self.delete_a_pod(namespace, pod_name)
                    if delete_time:
                        yield DeleteAPod(f"Pod Name: {pod_name} Deletion time: {delete_time}")

                # Try creating, patching and deleting an unprivileged pod
                pod_name = self.create_a_pod(namespace, False)
                if pod_name:
                    yield CreateAPod(f"Pod Name: {pod_name} Namespace: {namespace}")

                    patch_evidence = self.patch_a_pod(namespace, pod_name)
                    if patch_evidence:
                        yield PatchAPod(
                            f"Pod Name: {pod_name} " f"Namespace: {namespace} " f"Patch evidence: {patch_evidence}"
                        )

                    delete_time = self.delete_a_pod(namespace, pod_name)
                    if delete_time:
                        yield DeleteAPod(
                            f"Pod Name: {pod_name} " f"Namespace: {namespace} " f"Delete time: {delete_time}"
                        )

                role = self.create_a_role(namespace)
                if role:
                    yield CreateARole(f"Role name: {role}")

                    patch_evidence = self.patch_a_role(namespace, role)
                    if patch_evidence:
                        yield PatchARole(
                            f"Patched Role Name: {role} " f"Namespace: {namespace} " f"Patch evidence: {patch_evidence}"
                        )

                    delete_time = self.delete_a_role(namespace, role)
                    if delete_time:
                        yield DeleteARole(
                            f"Deleted role: {role} " f"Namespace: {namespace} " f"Delete time: {delete_time}"
                        )


@subscribe(ApiServer)
class ApiVersionHunter(Hunter):
    """Api Version Hunter
    Tries to obtain the Api Server's version directly from /version endpoint
    """

    def __init__(self, event):
        super().__init__(event)
        self.path = f"{self.event.protocol}://{self.event.host}:{self.event.port}"
        self.session = requests.Session()
        self.session.verify = False
        if self.event.auth_token:
            self.session.headers.update({"Authorization": f"Bearer {self.event.auth_token}"})

    def execute(self):
        config = get_config()
        if self.event.auth_token:
            logger.debug(
                "Trying to access the API server version endpoint using pod's"
                f" service account token on {self.event.host}:{self.event.port} \t"
            )
        else:
            logger.debug("Trying to access the API server version endpoint anonymously")
        version = self.session.get(f"{self.path}/version", timeout=config.network_timeout).json()["gitVersion"]
        logger.debug(f"Discovered version of api server {version}")
        yield K8sVersionDisclosure(version=version, from_endpoint="/version")
