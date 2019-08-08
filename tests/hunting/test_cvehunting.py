import time
import requests_mock

from src.core.events import handler
from src.core.events.types import K8sVersionDisclosure
from src.modules.hunting.cvehunter import K8sClusterCveHunter, ServerApiVersionEndPointAccessPE, ServerApiVersionEndPointAccessDos

cve_counter = 0

def test_K8sCveHunter():
    global cve_counter
    e = K8sVersionDisclosure(version="1.10.1", from_endpoint="/version")
    h = K8sClusterCveHunter(e)
    h.execute()

    time.sleep(0.01)
    assert cve_counter == 2
    cve_counter = 0

    # test complex version
    e = K8sVersionDisclosure(version="1.10.1-gke-1", from_endpoint="/version")
    h = K8sClusterCveHunter(e)
    h.execute()

    time.sleep(0.01)
    assert cve_counter == 2
    cve_counter = 0


@handler.subscribe(ServerApiVersionEndPointAccessPE)
class test_CVE_2018_1002105(object):
    def __init__(self, event):
        global cve_counter
        cve_counter += 1

@handler.subscribe(ServerApiVersionEndPointAccessDos)
class test_CVE_2019_1002100(object):
    def __init__(self, event):
        global cve_counter
        cve_counter += 1