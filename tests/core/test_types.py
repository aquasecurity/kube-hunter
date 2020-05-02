from kube_hunter.core.types import HunterBase, Service, Vulnerability


class TestHunterBase:
    def test_get_name_no_docstring(self):
        class NoDocHunter(HunterBase):
            pass

        expected = "NoDocHunter"
        actual = NoDocHunter.get_name()

        assert expected == actual

    def test_get_name_empty_docstring(self):
        class EmptyDocHunter(HunterBase):
            """"""

        expected = "EmptyDocHunter"
        actual = EmptyDocHunter.get_name()

        assert expected == actual

    def test_get_name_single_line_docstring(self):
        class SingleLineHunter(HunterBase):
            """Single Line Hunter"""

            pass

        expected = "Single Line Hunter"
        actual = SingleLineHunter.get_name()

        assert expected == actual

    def test_get_name_multi_line_docstring(self):
        class MultiLineHunter(HunterBase):
            """Multi Line Hunter

            There's some documentation here
            """

            pass

        expected = "Multi Line Hunter"
        actual = MultiLineHunter.get_name()

        assert expected == actual

    def test_get_name_leading_whitespace_docstring(self):
        class WhitespaceHunter(HunterBase):
            """
            Whitespace Hunter
            """

            pass

        expected = "Whitespace Hunter"
        actual = WhitespaceHunter.get_name()

        assert expected == actual


class TestService:
    def test_explain_with_doc(self):
        class DocumentedService(Service):
            """Some docs"""

            pass

        expected = "Some docs"
        service = DocumentedService(name="some name")
        actual = service.explain()

        assert expected == actual

    def test_explain_without_doc(self):
        class UndocumentedService(Service):
            pass

        expected = ""
        service = UndocumentedService(name="some name")
        actual = service.explain()

        assert expected == actual


class TestVulnerability:
    def test_explain_with_doc(self):
        class DocumentedVulnerability(Vulnerability):
            """Some docs"""

            pass

        expected = "Some docs"
        vulnerability = DocumentedVulnerability(name="some name", component=None)
        actual = vulnerability.explain()

        assert expected == actual

    def test_explain_without_doc(self):
        class UndocumentedVulnerability(Vulnerability):
            pass

        expected = ""
        vulnerability = UndocumentedVulnerability(name="some name", component=None)
        actual = vulnerability.explain()

        assert expected == actual
