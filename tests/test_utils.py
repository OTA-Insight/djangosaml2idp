import xml
from djangosaml2idp.utils import repr_saml, encode_saml

FILE_PREFIX = "tests/"

expected_result_file = open(FILE_PREFIX + "xml/min/request/sample_saml_request_minimal.xml")
expected_result = expected_result_file.readline()
expected_result_pretty = xml.dom.minidom.parseString(expected_result).toprettyxml()


# repr_saml and encode_saml are inverse functions. By testing them against each other, we test both.
class TestSAMLEncodeAndDecode:
    def test_with_minimal_saml_request_b64(self):
        assert repr_saml(encode_saml(expected_result), b64=True) == expected_result_pretty

    def test_with_internal_saml_response_zlib(self):
        assert repr_saml(encode_saml(expected_result, use_zlib=True)) == expected_result_pretty

