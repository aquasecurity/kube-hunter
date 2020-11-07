# flake8: noqa: E402
import requests_mock

from kube_hunter.conf import Config, set_config

set_config(Config())

from kube_hunter.modules.hunting.kubelet import ExposedRunHandler
from kube_hunter.modules.hunting.aks import AzureSpnHunter


def test_AzureSpnHunter():
    e = ExposedRunHandler()
    e.host = "mockKubernetes"
    e.port = 443
    e.protocol = "https"

    pod_template = '{{"items":[ {{"apiVersion":"v1","kind":"Pod","metadata":{{"name":"etc","namespace":"default"}},"spec":{{"containers":[{{"command":["sleep","99999"],"image":"ubuntu","name":"test","volumeMounts":[{{"mountPath":"/mp","name":"v"}}]}}],"volumes":[{{"hostPath":{{"path":"{}"}},"name":"v"}}]}}}} ]}}'

    bad_paths = ["/", "/etc", "/etc/", "/etc/kubernetes", "/etc/kubernetes/azure.json"]
    good_paths = ["/yo", "/etc/yo", "/etc/kubernetes/yo.json"]

    for p in bad_paths:
        with requests_mock.Mocker() as m:
            m.get("https://mockKubernetes:443/pods", text=pod_template.format(p))
            h = AzureSpnHunter(e)
            c = h.get_key_container()
            assert c

    for p in good_paths:
        with requests_mock.Mocker() as m:
            m.get("https://mockKubernetes:443/pods", text=pod_template.format(p))
            h = AzureSpnHunter(e)
            c = h.get_key_container()
            assert c == None

    with requests_mock.Mocker() as m:
        pod_no_volume_mounts = '{"items":[ {"apiVersion":"v1","kind":"Pod","metadata":{"name":"etc","namespace":"default"},"spec":{"containers":[{"command":["sleep","99999"],"image":"ubuntu","name":"test"}],"volumes":[{"hostPath":{"path":"/whatever"},"name":"v"}]}} ]}'
        m.get("https://mockKubernetes:443/pods", text=pod_no_volume_mounts)
        h = AzureSpnHunter(e)
        c = h.get_key_container()
        assert c == None

    with requests_mock.Mocker() as m:
        pod_no_volumes = '{"items":[ {"apiVersion":"v1","kind":"Pod","metadata":{"name":"etc","namespace":"default"},"spec":{"containers":[{"command":["sleep","99999"],"image":"ubuntu","name":"test"}]}} ]}'
        m.get("https://mockKubernetes:443/pods", text=pod_no_volumes)
        h = AzureSpnHunter(e)
        c = h.get_key_container()
        assert c == None

    with requests_mock.Mocker() as m:
        pod_other_volume = '{"items":[ {"apiVersion":"v1","kind":"Pod","metadata":{"name":"etc","namespace":"default"},"spec":{"containers":[{"command":["sleep","99999"],"image":"ubuntu","name":"test","volumeMounts":[{"mountPath":"/mp","name":"v"}]}],"volumes":[{"emptyDir":{},"name":"v"}]}} ]}'
        m.get("https://mockKubernetes:443/pods", text=pod_other_volume)
        h = AzureSpnHunter(e)
        c = h.get_key_container()
        assert c == None
