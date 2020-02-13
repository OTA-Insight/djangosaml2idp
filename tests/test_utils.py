import xml

from djangosaml2idp.utils import repr_saml, encode_saml


# repr_saml and encode_saml are inverse functions. By testing them against each other, we test both.
class TestSAMLEncodeAndDecode:
    def test_with_minimal_saml_request_b64(self, sample_saml_minimal):
        assert repr_saml(encode_saml(sample_saml_minimal), b64=True) == xml.dom.minidom.parseString(sample_saml_minimal).toprettyxml()

    def test_with_internal_saml_response_zlib(self, sample_saml_minimal):
        assert repr_saml(encode_saml(sample_saml_minimal, use_zlib=True)) == xml.dom.minidom.parseString(sample_saml_minimal).toprettyxml()
