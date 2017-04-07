# -*- coding: utf-8 -*-
from __future__ import (absolute_import, division, print_function,
                        unicode_literals)

import copy
import logging

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ImproperlyConfigured, PermissionDenied
from django.core.urlresolvers import reverse
from django.http import (HttpResponse, HttpResponseBadRequest,
                         HttpResponseRedirect, HttpResponseServerError)
from django.utils.datastructures import MultiValueDictKeyError
from django.utils.module_loading import import_string
from django.views.decorators.csrf import csrf_exempt
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.authn_context import PASSWORD, AuthnBroker, authn_context_class_ref
from saml2.config import IdPConfig
from saml2.ident import NameID
from saml2.metadata import entity_descriptor
from saml2.s_utils import UnknownPrincipal, UnsupportedBinding
from saml2.server import Server
from six import text_type

from .identity import create_identity
from .processors import BaseProcessor

logger = logging.getLogger(__name__)

try:
    idp_sp_config = settings.SAML_IDP_SPCONFIG
except AttributeError:
    raise ImproperlyConfigured("SAML_IDP_SPCONFIG not defined in settings.")


@csrf_exempt
def sso_entry(request):
    """ Entrypoint view for SSO. Gathers the parameters from the HTTP request, stores them in the session
        and redirects the requester to the login_process view.
    """
    passed_data = request.POST if request.method == 'POST' else request.GET
    try:
        request.session['SAMLRequest'] = passed_data['SAMLRequest']
    except (KeyError, MultiValueDictKeyError) as e:
        return HttpResponseBadRequest(e)
    request.session['RelayState'] = passed_data.get('RelayState', '')
    # TODO check how the redirect saml way works. Taken from example idp in pysaml2.
    if "SigAlg" in passed_data and "Signature" in passed_data:
        request.session['SigAlg'] = passed_data['SigAlg']
        request.session['Signature'] = passed_data['Signature']
    return HttpResponseRedirect(reverse('saml_login_process'))



# TODO Add http redirect logic based on https://github.com/rohe/pysaml2/blob/master/example/idp2_repoze/idp.py#L327
@login_required
def login_process(request):
    """ View which processes the actual SAML request and returns a self-submitting form with the SAML response.
        The login_required decorator ensures the user authenticates first on the IdP using 'normal' ways.
    """
    # Construct server with config from settings dict
    conf = IdPConfig()
    conf.load(copy.deepcopy(settings.SAML_IDP_CONFIG))
    IDP = Server(config=conf)
    # Parse incoming request
    try:
        req_info = IDP.parse_authn_request(request.session['SAMLRequest'], BINDING_HTTP_POST)
    except Exception as excp:
        return HttpResponseBadRequest(excp)
    # TODO this is taken from example, but no idea how this works or whats it does. Check SAML2 specification?
    # Signed request for HTTP-REDIRECT
    if "SigAlg" in request.session and "Signature" in request.session:
        _certs = IDP.metadata.certs(req_info.message.issuer.text, "any", "signing")
        verified_ok = False
        for cert in _certs:
            # TODO implement
            #if verify_redirect_signature(_info, IDP.sec.sec_backend, cert):
            #    verified_ok = True
            #    break
            pass
        if not verified_ok:
            return HttpResponseBadRequest("Message signature verification failure")

    binding_out, destination = IDP.pick_binding(
        service="assertion_consumer_service",
        entity_id=req_info.message.issuer.text)

    # Gather response arguments
    try:
        resp_args = IDP.response_args(req_info.message)
    except (UnknownPrincipal, UnsupportedBinding) as excp:
        return HttpResponseServerError(excp)
    
    try:
        sp_config = settings.SAML_IDP_SPCONFIG[resp_args['sp_entity_id']]
    except Exception:
        raise ImproperlyConfigured("No config for SP %s defined in SAML_IDP_SPCONFIG" % resp_args['sp_entity_id'])
    
    # Create user-specified processor or fallback to all-access base processor
    processor_string = sp_config.get('processor', None)
    if processor_string is None:
        processor = BaseProcessor
    else:
        processor_class = import_string(processor_string)
        processor = processor_class()
    
    # Check if user has access to the service of this SP
    if not processor.has_access(request.user):
        raise PermissionDenied

    # Create Identity dict (SP-specific)
    sp_mapping = sp_config.get('attribute_mapping', {'username': 'username'})
    identity = processor.create_identity(request.user, sp_mapping)

    # TODO investigate how this works, because I don't get it. Specification?
    req_authn_context = req_info.message.requested_authn_context or PASSWORD
    AUTHN_BROKER = AuthnBroker()
    AUTHN_BROKER.add(authn_context_class_ref(req_authn_context), "")

    # Construct SamlResponse message
    try:
        authn_resp = IDP.create_authn_response(
            identity=identity, userid=request.user.username,
            name_id=NameID(format=resp_args['name_id_policy'].format, sp_name_qualifier=destination, text=request.user.username),
            authn=AUTHN_BROKER.get_authn_by_accr(req_authn_context),
            sign_response=IDP.config.getattr("sign_response", "idp") or False,
            sign_assertion=IDP.config.getattr("sign_assertion", "idp") or False,
            **resp_args)
    except Exception as excp:
        return HttpResponseServerError(excp)

    # Return as html with self-submitting form.
    http_args = IDP.apply_binding(
        binding=binding_out,
        msg_str="%s" % authn_resp,
        destination=destination,
        relay_state=request.session['RelayState'],
        response=True)
    return HttpResponse(http_args['data'])


def metadata(request):
    """ Returns an XML with the SAML 2.0 metadata for this Idp.
        The metadata is constructed on-the-fly based on the config dict in the django settings.
    """
    conf = IdPConfig()
    conf.load(copy.deepcopy(settings.SAML_IDP_CONFIG))
    metadata = entity_descriptor(conf)
    return HttpResponse(content=text_type(metadata).encode('utf-8'), content_type="text/xml; charset=utf8")
