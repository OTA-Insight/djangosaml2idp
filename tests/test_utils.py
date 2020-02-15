import xml
from unittest import mock

import pytest
from django.core.exceptions import ValidationError

from djangosaml2idp.utils import encode_saml, fetch_metadata, repr_saml, validate_metadata, extract_validuntil_from_metadata

FILE_PREFIX = "tests/"

expected_result_file = open(FILE_PREFIX + "xml/min/request/sample_saml_request_minimal.xml")
expected_result = expected_result_file.readline()
expected_result_pretty = xml.dom.minidom.parseString(expected_result).toprettyxml()
expected_result_file.close()


# repr_saml and encode_saml are inverse functions. By testing them against each other, we test both.
class TestSAMLEncodeAndDecode:
    def test_with_minimal_saml_request_b64(self):
        assert repr_saml(encode_saml(expected_result), b64=True) == expected_result_pretty

    def test_with_internal_saml_response_zlib(self):
        assert repr_saml(encode_saml(expected_result, use_zlib=True)) == expected_result_pretty


# This method will be used by the mock to replace requests.get
def mocked_requests_get(*args, **kwargs):
    class MockResponse:
        def __init__(self, text, status_code):
            self.text = text
            self.status_code = status_code

    if args[0] == 'http://not_found':
        return MockResponse('not found', 404)

    return MockResponse('ok', 200)


class TestMetadataFetching:

    @mock.patch('requests.get', side_effect=mocked_requests_get)
    def test_fetch_metadata_nonexisting_url(self, mock_get):
        with pytest.raises(ValidationError):
            fetch_metadata('http://not_found')

    @mock.patch('requests.get', side_effect=mocked_requests_get)
    def test_fetch_metadata_working_url(self, mock_get):
        response = fetch_metadata('')
        assert response == 'ok'


class TestMetadataValidation:
    def test_validate_metadata_invalid(self):
        with pytest.raises(ValidationError):
            validate_metadata('')

    def test_validate_metadata_valid(self):
        md = validate_metadata('<?xml version="1.0" encoding="UTF-8"?><content></content>')
        assert md == '<?xml version="1.0" encoding="UTF-8"?><content></content>'

    def test_extract_validuntil_from_metadata_invalid(self):
        with pytest.raises(ValidationError):
            extract_validuntil_from_metadata('')
