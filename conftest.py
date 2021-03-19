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
def sp_metadata_xml(request) -> str:
    file_name = getattr(request, "param", "sp_metadata")
    with (XML_ROOT / f"metadata/{file_name}.xml").open("r") as f:
        return f.read()
