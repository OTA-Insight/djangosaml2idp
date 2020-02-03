import base64
import xml.dom.minidom
import zlib

from xml.parsers.expat import ExpatError


def repr_saml(saml: str, b64: bool = False):
    """ Decode SAML from b64 and b64 deflated and return a pretty printed representation
    """
    try:
        msg = base64.b64decode(saml).decode() if b64 else saml
        dom = xml.dom.minidom.parseString(msg)
    except (UnicodeDecodeError, ExpatError):
        # in HTTP-REDIRECT the base64 must be inflated
        msg = base64.b64decode(saml)
        inflated = zlib.decompress(msg, -15)
        dom = xml.dom.minidom.parseString(inflated.decode())
    return dom.toprettyxml()


def encode_saml(saml_envelope: str, use_zlib: bool = False) -> bytes:
    # Not sure where 2:-4 came from, but that's how pysaml2 does it, and it works
    before_base64 = zlib.compress(saml_envelope.encode())[2:-4] if use_zlib else saml_envelope.encode()
    return base64.b64encode(before_base64)
