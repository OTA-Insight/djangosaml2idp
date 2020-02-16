import xml
from unittest import mock

import arrow
import pytest
from django.core.exceptions import ValidationError

from djangosaml2idp.utils import (encode_saml,
                                  extract_validuntil_from_metadata,
                                  fetch_metadata, repr_saml, validate_metadata,
                                  verify_request_signature)

from .testing_utilities import mocked_requests_get

FILE_PREFIX = "tests/"

with open(FILE_PREFIX + "xml/metadata/sp_metadata.xml") as sp_metadata_xml_file:
    sp_metadata_xml = ''.join(sp_metadata_xml_file.readlines())

with open(FILE_PREFIX + "xml/min/request/sample_saml_request_minimal.xml") as expected_result_file:
    expected_result = expected_result_file.readline()
    expected_result_pretty = xml.dom.minidom.parseString(expected_result).toprettyxml()


class TestSAMLEncodeAndDecode:
    ''' repr_saml and encode_saml are inverse functions. By testing them against each other, we test both. '''
    def test_with_minimal_saml_request_b64(self):
        assert repr_saml(encode_saml(expected_result), b64=True) == expected_result_pretty

    def test_with_internal_saml_response_zlib(self):
        assert repr_saml(encode_saml(expected_result, use_zlib=True)) == expected_result_pretty


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

    def test_extract_validuntil_from_metadata_valid(self):
        valid_until_dt_extracted = extract_validuntil_from_metadata(sp_metadata_xml)
        assert valid_until_dt_extracted == arrow.get("2021-02-14T17:43:34Z")


class TestUtils:
    def test_verify_request_signature(self):
        # TODO: use real saml response
        class DummyStatusResponseFailing:
            xmlstr: str = ''

            def signature_check(self, *args, **kwargs):
                return False

        with pytest.raises(ValueError):
            verify_request_signature(DummyStatusResponseFailing())
