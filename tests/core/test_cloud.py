from kube_hunter.core.events.types.common import NewHostEvent


# Testing if it doesn't try to run get_cloud if the cloud type is already set.
# get_cloud(1.2.3.4) will result with an error
def test_presetcloud():
    expcted = "AWS"
    hostEvent = NewHostEvent(host="1.2.3.4", cloud=expcted)
    assert expcted == hostEvent.cloud


def test_getcloud():
    AZURE_SERVER = "52.224.188.147" # this is portal.azure.com DNS record
    expected = "Azure"
    hostEvent = NewHostEvent(host=AZURE_SERVER)
    
    assert hostEvent.cloud == expected
    