import copy
import logging

from django.conf import settings
from django.contrib.auth import logout
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import ImproperlyConfigured, PermissionDenied
from django.http import (HttpResponse, HttpResponseBadRequest,
                         HttpResponseRedirect, HttpResponseServerError)
from django.urls import reverse
from django.utils.datastructures import MultiValueDictKeyError
from django.utils.decorators import method_decorator
from django.utils.module_loading import import_string
from django.views import View
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from saml2 import BINDING_HTTP_POST
from saml2.authn_context import PASSWORD, AuthnBroker, authn_context_class_ref
from saml2.config import IdPConfig
from saml2.ident import NameID
from saml2.metadata import entity_descriptor
from saml2.s_utils import UnknownPrincipal, UnsupportedBinding
from saml2.server import Server
from six import text_type

from .processors import BaseProcessor

logger = logging.getLogger(__name__)

try:
    idp_sp_config = settings.SAML_IDP_SPCONFIG
except AttributeError:
    raise ImproperlyConfigured("SAML_IDP_SPCONFIG not defined in settings.")


@never_cache
@csrf_exempt
@require_http_methods(["GET", "POST"])
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
    return HttpResponseRedirect(reverse('djangosaml2idp:saml_login_process'))


@method_decorator(never_cache, name='dispatch')
class LoginProcessView(LoginRequiredMixin, View):
    """ View which processes the actual SAML request and returns a self-submitting form with the SAML response.
        The login_required decorator ensures the user authenticates first on the IdP using 'normal' ways.
    """

    def dispatch(self, request, *args, **kwargs):
        """ Construct server with config from settings dict
        """
        conf = IdPConfig()
        conf.load(copy.deepcopy(settings.SAML_IDP_CONFIG))
        self.IDP = Server(config=conf)
        return super(LoginProcessView, self).dispatch(request, *args, **kwargs)

    def get_processor(self, sp_config):
        """ "Instantiate user-specified processor or fallback to all-access base processor
        """
        processor_string = sp_config.get('processor', None)
        if processor_string:
            try:
                return import_string(processor_string)()
            except Exception as e:
                logger.error("Failed to instantiate processor: {} - {}".format(processor_string, e), exc_info=True)
        return BaseProcessor

    def get_identity(self, processor, user, sp_config):
        """ Create Identity dict (using SP-specific mapping)
        """
        sp_mapping = sp_config.get('attribute_mapping', {'username': 'username'})
        return processor.create_identity(user, sp_mapping)

    def get(self, request, *args, **kwargs):
        # Parse incoming request
        try:
            req_info = self.IDP.parse_authn_request(request.session['SAMLRequest'], BINDING_HTTP_POST)
        except Exception as excp:
            return HttpResponseBadRequest(excp)
        # TODO this is taken from example, but no idea how this works or whats it does. Check SAML2 specification?
        # Signed request for HTTP-REDIRECT
        if "SigAlg" in request.session and "Signature" in request.session:
            _certs = self.IDP.metadata.certs(req_info.message.issuer.text, "any", "signing")
            verified_ok = False
            for cert in _certs:
                # TODO implement
                #if verify_redirect_signature(_info, self.IDP.sec.sec_backend, cert):
                #    verified_ok = True
                #    break
                pass
            if not verified_ok:
                return HttpResponseBadRequest("Message signature verification failure")

        binding_out, destination = self.IDP.pick_binding(service="assertion_consumer_service", entity_id=req_info.message.issuer.text)

        # Gather response arguments
        try:
            resp_args = self.IDP.response_args(req_info.message)
        except (UnknownPrincipal, UnsupportedBinding) as excp:
            return HttpResponseServerError(excp)

        try:
            sp_config = settings.SAML_IDP_SPCONFIG[resp_args['sp_entity_id']]
        except Exception:
            raise ImproperlyConfigured("No config for SP %s defined in SAML_IDP_SPCONFIG" % resp_args['sp_entity_id'])

        processor = self.get_processor(sp_config)

        # Check if user has access to the service of this SP
        if not processor.has_access(request.user):
            raise PermissionDenied("You do not have access to this resource")

        identity = self.get_identity(processor, request.user, sp_config)

        # TODO investigate how this works, because I don't get it. Specification?
        req_authn_context = req_info.message.requested_authn_context or PASSWORD
        AUTHN_BROKER = AuthnBroker()
        AUTHN_BROKER.add(authn_context_class_ref(req_authn_context), "")

        # Construct SamlResponse message
        try:
            authn_resp = self.IDP.create_authn_response(
                identity=identity, userid=request.user.username,
                name_id=NameID(format=resp_args['name_id_policy'].format, sp_name_qualifier=destination, text=request.user.username),
                authn=AUTHN_BROKER.get_authn_by_accr(req_authn_context),
                sign_response=self.IDP.config.getattr("sign_response", "idp") or False,
                sign_assertion=self.IDP.config.getattr("sign_assertion", "idp") or False,
                **resp_args)
        except Exception as excp:
            return HttpResponseServerError(excp)

        http_args = self.IDP.apply_binding(
            binding=binding_out,
            msg_str="%s" % authn_resp,
            destination=destination,
            relay_state=request.session['RelayState'],
            response=True)

        logger.debug('http args are: %s' % http_args)

        return self.render_response(request, processor, http_args)

    def render_response(self, request, processor, http_args):
        """ Return either as redirect to MultiFactorView or as html with self-submitting form.
        """
        if processor.enable_multifactor(request.user):
            # Store http_args in session for after multi factor is complete
            request.session['saml_data'] = http_args['data']
            logger.debug("Redirecting to process_multi_factor")
            return HttpResponseRedirect(reverse('saml_multi_factor'))
        logger.debug("Performing SAML redirect")
        return HttpResponse(http_args['data'])


@method_decorator(never_cache, name='dispatch')
class ProcessMultiFactorView(LoginRequiredMixin, View):
    """ This view is used in an optional step is to perform 'other' user validation, for example 2nd factor checks.
        Override this view per the documentation if using this functionality to plug in your custom validation logic.
    """

    def multifactor_is_valid(self, request):
        """ The code here can do whatever it needs to validate your user (via request.user or elsewise).
            It must return True for authentication to be considered a success.
        """
        return True

    def get(self, request, *args, **kwargs):
        if self.multifactor_is_valid(request):
            logger.debug('MultiFactor succeeded for %s' % request.user)
            # If authentication succeeded, log in is ok
            return HttpResponse(request.session['saml_data'])
        logger.debug("MultiFactor failed; %s will not be able to log in" % request.user)
        logout(request)
        raise PermissionDenied("MultiFactor authentication factor failed")


@never_cache
def metadata(request):
    """ Returns an XML with the SAML 2.0 metadata for this Idp.
        The metadata is constructed on-the-fly based on the config dict in the django settings.
    """
    conf = IdPConfig()
    conf.load(copy.deepcopy(settings.SAML_IDP_CONFIG))
    metadata = entity_descriptor(conf)
    return HttpResponse(content=text_type(metadata).encode('utf-8'), content_type="text/xml; charset=utf8")
