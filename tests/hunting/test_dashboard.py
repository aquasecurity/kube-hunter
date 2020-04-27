import json

from types import SimpleNamespace
from requests_mock import Mocker
from kube_hunter.conf import Config, set_config

set_config(Config())

from kube_hunter.modules.hunting.dashboard import KubeDashboard  # noqa: E402


class TestKubeDashboard:
    @staticmethod
    def get_nodes_mock(result: dict, **kwargs):
        with Mocker() as m:
            m.get("http://mockdashboard:8000/api/v1/node", text=json.dumps(result), **kwargs)
            hunter = KubeDashboard(SimpleNamespace(host="mockdashboard", port=8000))
            return hunter.get_nodes()

    @staticmethod
    def test_get_nodes_with_result():
        nodes = {"nodes": [{"objectMeta": {"name": "node1"}}]}
        expected = ["node1"]
        actual = TestKubeDashboard.get_nodes_mock(nodes)

        assert expected == actual

    @staticmethod
    def test_get_nodes_without_result():
        nodes = {"nodes": []}
        expected = []
        actual = TestKubeDashboard.get_nodes_mock(nodes)

        assert expected == actual

    @staticmethod
    def test_get_nodes_invalid_result():
        expected = None
        actual = TestKubeDashboard.get_nodes_mock(dict(), status_code=404)

        assert expected == actual
