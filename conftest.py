from functools import lru_cache
from pathlib import Path

import pytest


XML_ROOT = Path(__file__).parent / "tests" / "xml"


@pytest.fixture()
@lru_cache()
def saml_request_minimal() -> str:
    with (XML_ROOT / "min/request/sample_saml_request_minimal.xml").open("r") as f:
        return f.read()


@pytest.fixture()
@lru_cache()
def sp_metadata_xml() -> str:
    with (XML_ROOT / "metadata/sp_metadata.xml").open("r") as f:
        return f.read()
