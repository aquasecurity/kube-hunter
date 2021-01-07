# flake8: noqa: E402
import requests_mock

from kube_hunter.conf import Config, set_config

import json

set_config(Config())

from kube_hunter.modules.hunting.kubelet import ExposedPodsHandler
from kube_hunter.modules.hunting.aks import AzureSpnHunter


def test_AzureSpnHunter():
    e = ExposedPodsHandler(pods=[])
    pod_template = '{{"items":[ {{"apiVersion":"v1","kind":"Pod","metadata":{{"name":"etc","namespace":"default"}},"spec":{{"containers":[{{"command":["sleep","99999"],"image":"ubuntu","name":"test","volumeMounts":[{{"mountPath":"/mp","name":"v"}}]}}],"volumes":[{{"hostPath":{{"path":"{}"}},"name":"v"}}]}}}} ]}}'

    bad_paths = ["/", "/etc", "/etc/", "/etc/kubernetes", "/etc/kubernetes/azure.json"]
    good_paths = ["/yo", "/etc/yo", "/etc/kubernetes/yo.json"]

    for p in bad_paths:
        e.pods = json.loads(pod_template.format(p))["items"]
        h = AzureSpnHunter(e)
        c = h.get_key_container()
        assert c

    for p in good_paths:
        e.pods = json.loads(pod_template.format(p))["items"]
        h = AzureSpnHunter(e)
        c = h.get_key_container()
        assert c == None

    pod_no_volume_mounts = '{"items":[ {"apiVersion":"v1","kind":"Pod","metadata":{"name":"etc","namespace":"default"},"spec":{"containers":[{"command":["sleep","99999"],"image":"ubuntu","name":"test"}],"volumes":[{"hostPath":{"path":"/whatever"},"name":"v"}]}} ]}'
    e.pods = json.loads(pod_no_volume_mounts)["items"]
    h = AzureSpnHunter(e)
    c = h.get_key_container()
    assert c == None

    pod_no_volumes = '{"items":[ {"apiVersion":"v1","kind":"Pod","metadata":{"name":"etc","namespace":"default"},"spec":{"containers":[{"command":["sleep","99999"],"image":"ubuntu","name":"test"}]}} ]}'
    e.pods = json.loads(pod_no_volumes)["items"]
    h = AzureSpnHunter(e)
    c = h.get_key_container()
    assert c == None

    pod_other_volume = '{"items":[ {"apiVersion":"v1","kind":"Pod","metadata":{"name":"etc","namespace":"default"},"spec":{"containers":[{"command":["sleep","99999"],"image":"ubuntu","name":"test","volumeMounts":[{"mountPath":"/mp","name":"v"}]}],"volumes":[{"emptyDir":{},"name":"v"}]}} ]}'
    e.pods = json.loads(pod_other_volume)["items"]
    h = AzureSpnHunter(e)
    c = h.get_key_container()
    assert c == None
