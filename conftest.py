from functools import lru_cache

import pytest

FILE_PREFIX = "tests/"


@pytest.fixture()
@lru_cache()
def sample_saml_minimal():
    with open(FILE_PREFIX + "xml/min/request/sample_saml_request_minimal.xml") as f:
        expected_result = f.readline()
    return expected_result
