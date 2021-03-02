import datetime
import xml
from unittest import mock

import pytest
from django.core.exceptions import ValidationError
from django.utils import timezone

from djangosaml2idp.utils import (encode_saml,
                                  extract_validuntil_from_metadata,
                                  fetch_metadata, repr_saml, validate_metadata,
                                  verify_request_signature)

from .testing_utilities import mocked_requests_get


class TestSAMLEncodeAndDecode:
    @staticmethod
    def prettify(xml_str: str) -> str:
        return xml.dom.minidom.parseString(xml_str).toprettyxml()

    ''' repr_saml and encode_saml are inverse functions. By testing them against each other, we test both. '''
    def test_with_minimal_saml_request_b64(self, saml_request_minimal):
        assert repr_saml(encode_saml(saml_request_minimal), b64=True) == self.prettify(saml_request_minimal)

    def test_with_internal_saml_response_zlib(self, saml_request_minimal):
        assert repr_saml(encode_saml(saml_request_minimal, use_zlib=True)) == self.prettify(saml_request_minimal)


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

    @pytest.mark.parametrize('use_tz, tzinfo', [(True, timezone.utc), (False, None)])
    def test_extract_validuntil_from_metadata_valid(self, settings, sp_metadata_xml, use_tz, tzinfo):
        settings.USE_TZ = use_tz
        valid_until_dt_extracted = extract_validuntil_from_metadata(sp_metadata_xml)
        assert valid_until_dt_extracted == datetime.datetime(2099, 2, 14, 17, 43, 34, tzinfo=tzinfo)


class TestUtils:
    def test_verify_request_signature(self):
        # TODO: use real saml response
        class DummyStatusResponseFailing:
            xmlstr: str = ''

            def signature_check(self, *args, **kwargs):
                return False

        with pytest.raises(ValueError):
            verify_request_signature(DummyStatusResponseFailing())
