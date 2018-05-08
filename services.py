from requests import get
from urllib3 import disable_warnings

UNKNOWN = 0
KUBERNETES_DASHBOARD = 1
KUBERNETES_PROXY = 2
KUBERNETES_KUBELET_HTTPS = 3
KUBERNETES_KUBELET_HTTP = 4

disable_warnings()


def describe_service_type(service_type):
    service_types = {
        KUBERNETES_DASHBOARD: "Kubernetes Dashboard",
        KUBERNETES_PROXY: "Kubernetes Proxy",
        KUBERNETES_KUBELET_HTTPS: "Kubernetes Kubelet",
        KUBERNETES_KUBELET_HTTP: "Kubernetes Kubelet (Read only)",
    }
    return service_types.get(service_type, "Unknown Service")


def is_dashboard(host):
    try:
        r = get("http://{}/api/v1/login/status".format(host)).json()
        return all([
            "tokenPresent" in r,
            "headerPresent" in r,
            "httpsMode" in r
        ])
    except:
        return False


def is_proxy(host):
    try:
        r = get("http://{}/".format(host)).json()
        return all([
            "paths" in r,
            "/api" in r["paths"]
        ])
    except:
        return False


def is_kubelet_https(host):
    try:
        r = get("https://{}/pods".format(host), verify=False).json()
        return all([
            "kind" in r,
            "items" in r
        ])
    except:
        return False


def is_kubelet_http(host):
    try:
        r = get("http://{}/pods".format(host)).json()
        return all([
            "kind" in r,
            "items" in r
        ])
    except:
        return False


def identify_service(host):
    if is_dashboard(host):
        return KUBERNETES_DASHBOARD

    if is_proxy(host):
        return KUBERNETES_PROXY

    if is_kubelet_https(host):
        return KUBERNETES_KUBELET_HTTPS

    if is_kubelet_http(host):
        return KUBERNETES_KUBELET_HTTP

    return UNKNOWN
