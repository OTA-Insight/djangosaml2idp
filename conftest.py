import pytest

FILE_PREFIX = "tests/"


@pytest.fixture()
def sample_saml_minimal():
    with open(FILE_PREFIX + "xml/min/request/sample_saml_request_minimal.xml") as f:
        expected_result = f.readline()
    return expected_result
