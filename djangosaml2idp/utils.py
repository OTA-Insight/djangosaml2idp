import base64
import datetime
import xml.dom.minidom
import xml.etree.ElementTree as ET
import zlib
from xml.parsers.expat import ExpatError

import arrow
import isodate
import requests
from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _
from saml2.response import StatusResponse


def repr_saml(saml: str, b64: bool = False):
    """ Decode SAML from b64 and b64 deflated and return a pretty printed representation
    """
    try:
        msg = base64.b64decode(saml).decode() if b64 else saml
        dom = xml.dom.minidom.parseString(msg)
    except (UnicodeDecodeError, ExpatError):
        # in HTTP-REDIRECT the base64 must be inflated
        compressed = base64.b64decode(saml)
        inflated = zlib.decompress(compressed, -15)
        dom = xml.dom.minidom.parseString(inflated.decode())
    return dom.toprettyxml()


def encode_saml(saml_envelope: str, use_zlib: bool = False) -> bytes:
    # Not sure where 2:-4 came from, but that's how pysaml2 does it, and it works
    before_base64 = zlib.compress(saml_envelope.encode())[2:-4] if use_zlib else saml_envelope.encode()
    return base64.b64encode(before_base64)


def verify_request_signature(req_info: StatusResponse) -> None:
    """ Signature verification for authn request signature_check is at
        saml2.sigver.SecurityContext.correctly_signed_authn_request
    """
    if not req_info.signature_check(req_info.xmlstr):
        raise ValueError(_("Message signature verification failure"))


def fetch_metadata(remote_metadata_url: str) -> str:
    ''' Fetch remote metadata. Raise a ValidationError if it could not successfully fetch something from the url '''
    try:
        content = requests.get(remote_metadata_url, timeout=(3, 10))
        if content.status_code != 200:
            raise Exception(f'Non-successful request, received status code {content.status_code}')
    except Exception as e:
        raise ValidationError(f'Could not fetch metadata from {remote_metadata_url}: {e}')
    return content.text


def validate_metadata(metadata: str) -> str:
    ''' Validate if the given metadata is valid xml, raise a ValidationError otherwise. Returns the metadata string back.
    '''
    try:
        ET.fromstring(metadata)
    except Exception as e:
        raise ValidationError(f'Metadata is not valid metadata xml: {e}')
    return metadata


def extract_validuntil_from_metadata(metadata: str) -> datetime.datetime:
    ''' Extract the expiration timestamp from the given metadata. Returns a timestamp if successfully, raise a ValidationError otherwise.
        The expiration timestamp can be extracted using either the ValidUntil or the CacheDuration property.
    '''

    metadata_el = ET.fromstring(metadata)

    metadata_expiration_dt = None
    if 'validUntil' in metadata_el.attrib:
        try:
            metadata_expiration_dt = arrow.get(metadata_el.attrib['validUntil']).datetime
        except Exception as e:
            raise ValidationError(f'Error extracting ValidUntil timestamp from metadata: {e}')

    cache_expiration_dt = None
    if 'cacheDuration' in metadata_el.attrib:
        try:
            time_delta = isodate.parse_duration(metadata_el.attrib['cacheDuration'])
            cache_expiration_dt = (arrow.get() + time_delta).datetime
        except Exception as e:
            raise ValidationError(f'Error extracting cacheDuration from metadata: {e}')

    if metadata_expiration_dt is None and cache_expiration_dt is None:
        raise ValidationError('Neither "validUntil" or "cacheDuration" are present in the metdata')

    return metadata_expiration_dt, cache_expiration_dt
