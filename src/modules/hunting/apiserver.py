import logging
import json
import requests

from ...core.events import handler
from ...core.events.types import Vulnerability, Event, OpenPortEvent
from ...core.types import Hunter, ActiveHunter, KubernetesCluster, RemoteCodeExec, AccessRisk, InformationDisclosure


""" Vulnerabilities """


class ServerApiAccess(Vulnerability, Event):
    """ Accessing the server API within a compromised pod would help an attacker gain full control over the cluster"""

    def __init__(self, evidence):
        Vulnerability.__init__(self, KubernetesCluster, name="Accessed to server API", category=RemoteCodeExec)
        self.evidence = evidence


class ServiceAccountTokenAccess(Vulnerability, Event):
    """ Accessing the pod's service account token gives an attacker the option to use the server API """

    def __init__(self, evidence):
        Vulnerability.__init__(self, KubernetesCluster, name="Read access to pod's service account token",
                               category=AccessRisk)
        self.evidence = evidence


class ListPodUnderDefaultNamespace(Vulnerability, Event):
    """ Accessing the pods list under default namespace within a compromised pod might grant an attacker a valuable
     information to harm the cluster """

    def __init__(self, evidence):
        Vulnerability.__init__(self, KubernetesCluster, name="Access to the pods list under default namespace",
                               category=InformationDisclosure)
        self.evidence = evidence


class ListPodUnderAllNamespaces(Vulnerability, Event):
    """ Accessing the pods list under ALL of the namespaces within a compromised pod might grant an attacker a valuable
     information to harm the cluster """

    def __init__(self, evidence):
        Vulnerability.__init__(self, KubernetesCluster, name="Access to the pods list under ALL namespaces",
                               category=InformationDisclosure)
        self.evidence = evidence


class ListAllNamespaces(Vulnerability, Event):
    """ Accessing all of the namespaces within a compromised pod might grant an attacker a valuable information
    """

    def __init__(self, evidence):
        Vulnerability.__init__(self, KubernetesCluster, name="Access to the all namespaces list",
                               category=InformationDisclosure)
        self.evidence = evidence


class ListAllRoles(Vulnerability, Event):
    """ Accessing all of the namespaces within a compromised pod might grant an attacker a valuable information
    """

    def __init__(self, evidence):
        Vulnerability.__init__(self, KubernetesCluster, name="Access to the all roles list",
                               category=InformationDisclosure)
        self.evidence = evidence


class ListAllClusterRoles(Vulnerability, Event):
    """ Accessing all of the namespaces within a compromised pod might grant an attacker a valuable information
    """

    def __init__(self, evidence):
        Vulnerability.__init__(self, KubernetesCluster, name="Access to the all cluster roles list",
                               category=InformationDisclosure)
        self.evidence = evidence


class CreateANamespace(Vulnerability, Event):

    """ Creating a namespace might give an attacker an area with default (exploitable) permissions to run pod in.
    """
    def __init__(self, evidence):
        Vulnerability.__init__(self, KubernetesCluster, name="Created a role",
                               category=InformationDisclosure)
        self.evidence = evidence


class CreateARole(Vulnerability, Event):
    """ Creating a role might give an attacker the option to harm the normal routine of newly created pods
     within the specified namespaces.
    """

    def __init__(self, evidence):
        Vulnerability.__init__(self, KubernetesCluster, name="Created a role",
                               category=InformationDisclosure)
        self.evidence = evidence


class CreateAClusterRole(Vulnerability, Event):
    """ Creating a role might give an attacker the option to harm the normal routine of newly created pods within the
    whole cluster scope.
    """

    def __init__(self, evidence):
        Vulnerability.__init__(self, KubernetesCluster, name="Created a cluster role",
                               category=InformationDisclosure)
        self.evidence = evidence


class PatchARole(Vulnerability, Event):
    """ Patching a cluster role might give an attacker the option to create new pods with custom roles within the
    specific role's namespace scope
    """

    def __init__(self, evidence):
        Vulnerability.__init__(self, KubernetesCluster, name="Patched a role",
                               category=InformationDisclosure)
        self.evidence = evidence


class PatchAClusterRole(Vulnerability, Event):
    """ Patching a cluster role might give an attacker the option to create new pods with custom roles within the whole
    cluster scope.
    """

    def __init__(self, evidence):
        Vulnerability.__init__(self, KubernetesCluster, name="Patched a cluster role",
                               category=InformationDisclosure)
        self.evidence = evidence


class DeleteARole(Vulnerability, Event):
    """ Deleting a role might give an attacker the option to create new pods with custom roles within a specific role's
    namespace scope."""

    def __init__(self, evidence):
        Vulnerability.__init__(self, KubernetesCluster, name="Deleted a role",
                               category=InformationDisclosure)
        self.evidence = evidence


class DeleteAClusterRole(Vulnerability, Event):
    """ Deleting a cluster role might give an attacker the option to create new pods with custom roles within the whole
    cluster scope."""

    def __init__(self, evidence):
        Vulnerability.__init__(self, KubernetesCluster, name="Deleted a cluster role",
                               category=InformationDisclosure)
        self.evidence = evidence


class CreateAPod(Vulnerability, Event):
    """ Creating a new pod would gain an attacker the option to compromise another (newly created) pod"""

    def __init__(self, evidence):
        Vulnerability.__init__(self, KubernetesCluster, name="Created A Pod",
                               category=InformationDisclosure)
        self.evidence = evidence


class PatchAPod(Vulnerability, Event):
    """ Patching pod would gain an attacker the option to compromise other pod, and control it """

    def __init__(self, evidence):
        Vulnerability.__init__(self, KubernetesCluster, name="Patched A Pod",
                               category=InformationDisclosure)
        self.evidence = evidence


class DeleteAPod(Vulnerability, Event):
    """ Deleting a pod from within a compromised pod might gain an attacker the option to disturbe cluster\'s
     normal behaviour."""

    def __init__(self, evidence):
        Vulnerability.__init__(self, KubernetesCluster, name="Deleted A Pod",
                               category=InformationDisclosure)
        self.evidence = evidence


class ApiServerPassiveHunterFinished(Event):
    def __init__(self, all_namespaces_names, service_account_token):
        self.all_namespaces_names = all_namespaces_names
        self.service_account_token = service_account_token

    def __str__(self):
        return str(self.service_account_token)

# Passive Hunter
@handler.subscribe(OpenPortEvent, predicate=lambda x: x.port == 443 or x.port == 6443)
class AccessApiServerViaServiceAccountToken(Hunter):
    """ API Server Hunter
    Accessing the api server within a compromised pod might grant an attacker full control over the cluster
    """

    def __init__(self, event):
        self.event = event
        self.api_server_evidence = ''
        self.service_account_token_evidence = ''
        self.pod_list_under_default_namespace_evidence = ''
        self.pod_list_under_all_namespaces_evidence = ''
        self.newly_created_cluster_role_name_evidence = ''
        self.newly_created_role_name_evidence = ''
        self.all_namespaces_names_evidence = list()
        self.all_roles_names_evidence = ''
        self.all_cluster_roles_names_evidence = ''
        self.namespaces_and_their_pod_names = dict()

    def access_api_server(self):
        logging.debug(self.event.host)
        logging.debug('Passive Hunter is attempting to access the API server using the pod\'s service account token')
        try:
            res = requests.get("https://{host}:{port}/api".format(host=self.event.host, port=self.event.port),
                               headers={'Authorization': 'Bearer ' + self.service_account_token_evidence}, verify=False)
            self.api_server_evidence = res.content
            return res.status_code == 200 and res.content != ''
        except requests.exceptions.ConnectionError:  # e.g. DNS failure, refused connection, etc
            return False

    def get_service_account_token(self):
        logging.debug(self.event.host)
        logging.debug('Passive Hunter is attempting to access pod\'s service account token')
        try:
            with open('/var/run/secrets/kubernetes.io/serviceaccount/token', 'r') as token:
                data = token.read()
                self.service_account_token_evidence = data
                return True
        except IOError:  # Couldn't read file
            return False

    # 2 Pods Methods:
    # --> V
    def get_pods_list_under_default_namespace(self):
        try:
            res = requests.get("https://{host}:{port}/api/v1/namespaces/default/pods".format(host=self.event.host,
                                port=self.event.port),
                               headers={'Authorization': 'Bearer ' + self.service_account_token_evidence}, verify=False)

            parsed_response_content = json.loads(res.content.replace('\'', '\"'))
            for item in parsed_response_content["items"]:
                self.namespaces_and_their_pod_names[item["metadata"]["name"]] = item["metadata"]["name"]

            return res.status_code == 200 and res.content != ''
        except requests.exceptions.ConnectionError:  # e.g. DNS failure, refused connection, etc
            return False

    # --> V
    def get_pods_list_under_all_namespace(self):
        try:
            res = requests.get("https://{host}:{port}/api/v1/pods".format(host=self.event.host, port=self.event.port),
                               headers={'Authorization': 'Bearer ' + self.service_account_token_evidence}, verify=False)

            parsed_response_content = json.loads(res.content.replace('\'', '\"'))
            for item in parsed_response_content["items"]:
                self.namespaces_and_their_pod_names[item["metadata"]["name"]] = item["metadata"]["name"]

            return res.status_code == 200 and res.content != ''
        except requests.exceptions.ConnectionError:  # e.g. DNS failure, refused connection, etc
            return False

    # 1 Namespace method:
    # --> V
    def get_all_namespaces(self):
        try:
            res = requests.get("https://{host}:{port}/api/v1/namespaces".format(host=self.event.host,
                                                                                port=self.event.port),
                               headers={'Authorization': 'Bearer ' + self.service_account_token_evidence},
                               verify=False)

            parsed_response_content = json.loads(res.content.replace('\'', '\"'))
            for item in parsed_response_content["items"]:
                self.all_namespaces_names_evidence.append(item["metadata"]["name"])
            return res.status_code == 200 and res.content != ''
        except requests.exceptions.ConnectionError:  # e.g. DNS failure, refused connection, etc
            return False

    # 3 Roles & Cluster Roles Methods:
    #  --> V
    def get_roles_under_namespace(self, namespace):
        try:
            res = requests.get("https://{host}:{port}/apis/rbac.authorization.k8s.io/v1/namespaces/{namespace}/roles".format(
                                 host=self.event.host, port=self.event.port, namespace=namespace),
                               headers={'Authorization': 'Bearer ' + self.service_account_token_evidence}, verify=False)
            self.namespace_roles_evidence = res.content
            return res.content if res.status_code == 200 and res.content != '' else False
        except requests.exceptions.ConnectionError:
            return False

    #  --> V
    def get_all_cluster_roles(self):
        try:
            res = requests.get("https://{host}:{port}/apis/rbac.authorization.k8s.io/v1/clusterroles".format(
                                 host=self.event.host, port=self.event.port),
                               headers={'Authorization': 'Bearer ' + self.service_account_token_evidence}, verify=False)
            self.namespace_roles_evidence = res.content
            return res.content if res.status_code == 200 and res.content != '' else False
        except requests.exceptions.ConnectionError:
            return False

    #  --> V
    def get_all_roles(self):
        try:
            res = requests.get("https://{host}:{port}/apis/rbac.authorization.k8s.io/v1/roles".format(
                                 host=self.event.host, port=self.event.port),
                               headers={'Authorization': 'Bearer ' + self.service_account_token_evidence}, verify=False)
            self.namespace_roles_evidence = res.content
            return res.content if res.status_code == 200 and res.content != '' else False
        except requests.exceptions.ConnectionError:
            return False

    def execute(self):
        if self.get_service_account_token():
            self.publish_event(ServiceAccountTokenAccess(self.service_account_token_evidence))
            if self.access_api_server():
                self.publish_event(ServerApiAccess(self.api_server_evidence))
            try:
                if self.get_all_namespaces():
                    self.publish_event(ListAllNamespaces(self.all_namespaces_names_evidence))

                if self.get_pods_list_under_all_namespace():
                    self.publish_event(ListPodUnderAllNamespaces(self.pod_list_under_all_namespaces_evidence))
                else:
                    if self.get_pods_list_under_default_namespace():
                        self.publish_event(ListPodUnderDefaultNamespace(self.pod_list_under_default_namespace_evidence))

                if self.get_all_roles():
                    self.publish_event(ListAllRoles(self.all_roles_names_evidence))

                if self.get_all_cluster_roles():
                    self.publish_event(ListAllClusterRoles(self.all_cluster_roles_names_evidence))

                #  At this point we know we got the service_account_token, and we might got all of the namespaces
                self.publish_event(ApiServerPassiveHunterFinished(self.service_account_token_evidence,
                                                                  self.pod_list_under_all_namespaces_evidence))

            except Exception:
                import traceback
                traceback.print_exc()


# Active Hunter
@handler.subscribe(ApiServerPassiveHunterFinished, predicate=lambda event: event.service_account_token != '')
class AccessApiServerViaServiceAccountTokenActive(ActiveHunter):
    """API server hunter
    Accessing the api server might grant an attacker full control over the cluster
    """

    def __init__(self, event):
        self.event = event

        # Getting Passive hunter's data:
        self.namespaces_and_their_pod_names = dict()
        self.all_namespaces_names = set(event.all_namespaces_names)
        self.service_account_token = event.service_account_token

        # 10 Evidences:
        self.created_pod_name_evidence = ''
        self.patched_newly_created_pod_evidence = ''
        self.deleted_newly_created_pod_evidence = ''

        self.created_role_evidence = ''
        self.patched_newly_created_role_evidence = ''
        self.deleted_newly_created_role_evidence = ''

        self.created_cluster_role_evidence = ''
        self.patched_newly_created_cluster_role_evidence = ''
        self.deleted_newly_created_cluster_role_evidence = ''

        self.created_new_namespace_name_evidence = ''

    # 3 Pod methods:
    # --> V
    def create_a_pod(self, namespace):
        try:
            jsonPod = \
            """
                "apiVersion": "v1",            
                "kind": "Pod",
                "metadata": {
                    "name": "nginx1"
                },
                "spec": {
                    "containers": [
                        {
                            "name": "nginx",
                            "image": "nginx:1.7.9",
                            "ports": [
                                {
                                    "containerPort": 80
                                }
                            ]
                        }
                    ]
                }
            }
            """
            headers = {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer {token}'.format(token=self.service_account_token_evidence)
            }
            res = requests.post("https://{host}:{port}/api/v1/namespaces/{namespace}/pods".format(
                                host=self.event.host, port=self.event.port, namespace=namespace),
                                verify=False, data=jsonPod, headers=headers)
            self.self.created_pod_name_evidence = res.content['metadata']['name']
            return res.status_code in [200, 201, 202] and res.content != ''
        except (requests.exceptions.ConnectionError, KeyError):
            return False

    # --> V
    def delete_a_pod(self, pod_name, namespace):
        try:
            res = requests.delete("https://{host}:{port}/api/v1/namespaces/{namespace}/pods/{name}".format(
                                 host=self.event.host, port=self.event.port, name=pod_name, namespace=namespace),
                               headers={'Authorization': 'Bearer ' + self.service_account_token_evidence}, verify=False)
            self.deleted_newly_created_pod_evidence = res.content['metadata']['deletionTimestamp']
            return res.status_code == 200 and res.content != ''
        except (requests.exceptions.ConnectionError, KeyError):
            return False

    def patch_a_pod(self, pod_namespace, pod_name):
        try:
            patch_data = {}
            res = requests.patch("https://{host}:{port}/api/v1/namespaces/{namespace}/pods/{name}".format(
                                 host=self.event.host, port=self.event.port, namespace=pod_namespace, name=pod_name),
                               headers={'Authorization': 'Bearer ' + self.service_account_token_evidence}, verify=False, data=patch_data)
            self.patched_newly_created_pod = res.content['metadata']   # DECIDE WHAT EVIDENCE HERE
            return res.status_code == 200 and res.content != ''
        except (requests.exceptions.ConnectionError, KeyError):
            return False

    # 1 Namespaces method:
    # --> V
    def create_namespace(self):
        #  Initialize variables:
        json_namespace = \
            """
                apiVersion: v1
                kind: Namespace
                metadata:
                  name: new-namespace
            """
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer {token}'.format(token=self.service_account_token_evidence)
        }
        #  Do request
        try:
            res = requests.post("https://{host}:{port}/api/v1/namespaces".format(
                host=self.event.host, port=self.event.port),
                verify=False, data=json_namespace, headers=headers)

            self.created_new_namespace_name_evidence = res.content['metadata']['name']
            self.all_namespaces_names.add(self.new_namespace_name_evidenc)

            return res.status_code in [200, 201, 202] and res.content != ''
        except requests.exceptions.ConnectionError:  # e.g. DNS failure, refused connection, etc
            return False

    #  6 Roles & Cluster roles Methods:
    # --> V
    def create_a_role(self, namespace):
        try:
            res = requests.post("https://{host}:{port}/apis/rbac.authorization.k8s.io/v1/namespaces/{namespace}/roles".format(
                                host=self.event.host, port=self.event.port, namespace=namespace),
                                headers={'Authorization': 'Bearer ' + self.service_account_token_evidence}, verify=False)
            self.created_role_evidence = res.content['items'][0]['metadata']['name']
            return res.content if res.status_code in [200, 201, 202] and res.content != '' else False
        except (requests.exceptions.ConnectionError, KeyError):
            return False

    # --> V
    def create_a_cluster_role(self):
        try:
            res = requests.post("https://{host}:{port}/apis/rbac.authorization.k8s.io/v1/clusterroles".format(
                               host=self.event.host, port=self.event.port),
                               headers={'Authorization': 'Bearer ' + self.service_account_token_evidence}, verify=False)
            self.created_cluster_role_evidence = res.content['items'][0]['metadata']['name']
            return res.content if res.status_code in [200, 201, 202] and res.content != '' else False
        except (requests.exceptions.ConnectionError, KeyError):
            return False

    # --> V
    def delete_a_role(self, namespace_name, newly_created_role_name):
        try:
            res = requests.delete("https://{host}:{port}/apis/rbac.authorization.k8s.io/v1/namespaces/{namespace}/roles/{role}".format(
                                 host=self.event.host, port=self.event.port, namespace=namespace_name, role=newly_created_role_name),
                               headers={'Authorization': 'Bearer ' + self.service_account_token_evidence}, verify=False)
            self.deleted_newly_created_role_evidence = res.content["status"]
            return res.content if res.status_code == 200 and res.content != '' else False
        except (requests.exceptions.ConnectionError, KeyError):
            return False

    def delete_a_cluster_role(self, newly_created_cluster_role_name):
        try:
            res = requests.delete("https://{host}:{port}/apis/rbac.authorization.k8s.io/v1/clusterroles/{name}".format(
                                 host=self.event.host, port=self.event.port, name=newly_created_cluster_role_name),
                               headers={'Authorization': 'Bearer ' + self.service_account_token_evidence}, verify=False)
            self.deleted_newly_created_cluster_role_evidence = res.content["status"]
            return res.content if res.status_code == 200 and res.content != '' else False
        except (requests.exceptions.ConnectionError, KeyError):
            return False

    def patch_a_role(self, newly_created_role_name, newly_created_namespace_name):
        data = """{
            [
                {"op": "add", "path": "/hello", "value": ["world"]}
            ]
        }"""
        try:
            res = requests.patch("https://{host}:{port}/apis/rbac.authorization.k8s.io/v1/namespaces/{namespace}/roles/{name}".format(
                                 host=self.event.host, port=self.event.port, name=newly_created_role_name,
                                 namespace=newly_created_namespace_name),
                                 headers={'Authorization': 'Bearer ' + self.service_account_token_evidence},
                                 verify=False, data=data)
            self.patched_newly_created_cluster_role_evidence = res.content
            return res.content if res.status_code == 200 and res.content != '' else False
        except (requests.exceptions.ConnectionError, KeyError):
            return False

    def patch_a_cluster_role(self, newly_created_cluster_role_name):
        data = """{
            [
                {"op": "add", "path": "/hello", "value": ["world"]}
            ]
        }"""
        try:
            res = requests.patch("https://{host}:{port}/apis/rbac.authorization.k8s.io/v1/clusterroles/{name}".format(
                                 host=self.event.host, port=self.event.port, name=newly_created_cluster_role_name),
                                 headers={'Authorization': 'Bearer ' + self.service_account_token_evidence},
                                 verify=False, data=data)
            self.patched_newly_created_cluster_role_evidence = res.content
            return res.content if res.status_code == 200 and res.content != '' else False
        except (requests.exceptions.ConnectionError, KeyError):
            return False

    def execute(self):

        if self.service_account_token_evidence != '':
            if self.create_namespace():
                self.publish_event(self.CreateANamespace('new namespace name: {name}'.
                                                         format(name=self.new_namespace_name_evidence)))
            if self.create_a_cluster_role():
                self.publish_event(CreateAClusterRole('Cluster role name:  {name}'.format(
                                                      name=self.created_cluster_role_evidence)))
                if self.patch_a_cluster_role(self.newly_created_cluster_role_name_evidence):  #  TODO: add evidences when publishing events

                    self.publish_event(PatchAClusterRole('Patched Cluster Role Name:  {name}'.format(
                                                         name=self.patched_newly_created_cluster_role_evidence)))

                if self.delete_a_cluster_role(self.newly_created_cluster_role_name_evidence):
                    self.publish_event(DeleteAClusterRole('Cluster role deletion time:  {time}'.format(
                                                          time=self.deleted_newly_created_cluster_role_evidence)))

            if self.create_a_role():
                self.publish_event(CreateAClusterRole('Role name:  {name}'.format(
                                                     name=self.created_role_evidence)))

                if self.patch_a_role(self.newly_created_cluster_role_name_evidence):  #  TODO: add evidences when publishing events
                    self.publish_event(PatchARole('Patched Role Name:  {name}'.format(
                                                         name=self.patched_newly_created_role_evidence)))

                if self.delete_a_role(self.newly_created_cluster_role_name_evidence):
                    self.publish_event(DeleteARole('Role deletion time: {time}'.format(
                                                   time=self.delete_a_role())))

            #  Operating on pods over all namespaces:
            for namespace in self.all_namespaces_evidence:
                if self.create_a_pod(namespace):
                    self.publish_event(CreateAPod('Pod Name: {pod_name}  Pod Namespace:{pod_namespace}'.format(
                                                  pod_name=self.created_pod_name_evidence, pod_namespace=namespace)))

                    #  TODO- finish patch a pod method:
                    if self.patch_a_pod(namespace, self.new_pod_name_evidence):
                        self.publish_event(PatchAPod('Pod Name: {pod_name}  {patch_evidence}'.format(
                                                     pod_name=self.created_pod_name_evidence,
                                                     patch_evidence=self.patched_newly_created_pod_evidence)))

                    if self.delete_a_pod(namespace, self.new_pod_name_evidence):
                        self.publish_event(DeleteAPod('Pod Name: {pod_name}  {delete_evidence}'.format(
                                                     pod_name=self.created_pod_name_evidence,
                                                     delete_evidence=self.deleted_newly_created_pod_evidence)))


            #  TODO- Implement the following algorithm:
            # Algorithm in words:

            # This hunter should be triggered only when 443 or 6443 port are open AND the passive hunter
            # --have published it to start

            # (1) Get All data from the passive hunter.
            # (2) Attempt to create a cluster role, patch it, and delete it.
            # (2) Attempt to create a new namespace.
            # (3) Attempt to create a pod/s in all namespaces found (or just default namespace if none found)
                # (3.1) Attempt to patch newly created pod/s in all namespaces found (or just default namespace if none
                # -- found and we were able to create a pod in it)
                # (3.2) Attempt to delete newly created pod/s in all namespaces found (or just default namespace if none
                # -- found and we were able to create a pod in it
            # (4) Attempt to create a role/s in all of the namespaces (or just default namespace if none found)
                # (4.1) Attempt to patch newly created role/s in all of the namespaces (or just default namespace if
                # -- none found and we were able to create a role on it)
                # (4.2) Attempt to delete newly created role/s in all of the namespaces (or just default namespace if
                # -- none found and we were able to create a role on it)

            #  Note: we are not binding any role or cluster role because
            # -- it might effect the cluster (and we are not allowed to do that)
