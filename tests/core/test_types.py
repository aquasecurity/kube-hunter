from kube_hunter.core.types import HunterBase


def test_parse_docs_empty():
    expected = ("kube_hunter.core.types", "<no documentation>")
    actual = HunterBase.parse_docs("")
    assert actual == expected


def test_parse_docs_only_header():
    docs = "SomeHunter"
    expected = ("SomeHunter", "<no documentation>")
    actual = HunterBase.parse_docs(docs)
    assert actual == expected


def test_parse_docs_with_body():
    docs = "SomeHunter\n Very \n interesting hunter. "
    expected = ("SomeHunter", "Very interesting hunter.")
    actual = HunterBase.parse_docs(docs)
    assert actual == expected


def test_hunter_base_get_name():
    class SomeHunter(HunterBase):
        """SomeHunter
        This is a test hunter
        """
    assert SomeHunter.get_name() == "SomeHunter"
