import xml

import pytest

FILE_PREFIX = "tests/"


@pytest.fixture()
def sample_saml_minimal():
    with open(FILE_PREFIX + "xml/min/request/sample_saml_request_minimal.xml") as f:
        expected_result = f.readline()
    return expected_result


@pytest.fixture()
def sample_saml_minimal_pretty(sample_saml_minimal):
    return xml.dom.minidom.parseString(sample_saml_minimal).toprettyxml()
