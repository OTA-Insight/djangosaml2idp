import base64
import copy
import logging

from django.conf import settings
from django.contrib.auth import logout
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import ImproperlyConfigured, PermissionDenied
from django.http import (HttpResponse, HttpResponseBadRequest, HttpResponseRedirect)
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils.datastructures import MultiValueDictKeyError
from django.utils.decorators import method_decorator
from django.utils.module_loading import import_string
from django.views import View
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.authn_context import PASSWORD, AuthnBroker, authn_context_class_ref
from saml2.config import IdPConfig
from saml2.ident import NameID
from saml2.metadata import entity_descriptor
from saml2.s_utils import UnknownPrincipal, UnsupportedBinding
from saml2.saml import NAMEID_FORMAT_UNSPECIFIED
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
    if request.method == 'POST':
        passed_data = request.POST
        binding = BINDING_HTTP_POST
    else:
        passed_data = request.GET
        binding = BINDING_HTTP_REDIRECT

    request.session['Binding'] = binding

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


class IdPHandlerViewMixin:
    """ Contains some methods used by multiple views """

    error_view = import_string(getattr(settings, 'SAML_IDP_ERROR_VIEW_CLASS', 'djangosaml2idp.error_views.SamlIDPErrorView'))

    def handle_error(self, request, **kwargs):
        return self.error_view.as_view()(request, **kwargs)

    def dispatch(self, request, *args, **kwargs):
        """ Construct IDP server with config from settings dict
        """
        conf = IdPConfig()
        try:
            conf.load(copy.deepcopy(settings.SAML_IDP_CONFIG))
            self.IDP = Server(config=conf)
        except Exception as e:
            return self.handle_error(request, exception=e)
        return super().dispatch(request, *args, **kwargs)

    def set_sp(self, sp_entity_id):
        self.sp = {'id': sp_entity_id}
        try:
            self.sp['config'] = settings.SAML_IDP_SPCONFIG[sp_entity_id]
        except KeyError:
            raise ImproperlyConfigured("No config for SP {} defined in SAML_IDP_SPCONFIG".format(sp_entity_id))

    def set_processor(self):
        """ Instantiate user-specified processor or default to an all-access base processor.
            Raises an exception if the configured processor class can not be found or initialized.
        """
        processor_string = self.sp['config'].get('processor', None)
        if processor_string:
            try:
                self.processor = import_string(processor_string)(self.sp['id'])
            except Exception as e:
                logger.error("Failed to instantiate processor: {} - {}".format(processor_string, e), exc_info=True)
                raise
        self.processor = BaseProcessor(self.sp['id'])

    def get_identity(self, user):
        """ Create Identity dict (using SP-specific mapping)
        """
        sp_mapping = self.sp['config'].get('attribute_mapping', {'username': 'username'})
        return self.processor.create_identity(user, sp_mapping, **self.sp['config'].get('extra_config', {}))

    def get_authn(self, req_info=None):
        req_authn_context = req_info.message.requested_authn_context if req_info else PASSWORD
        AUTHN_BROKER = AuthnBroker()
        AUTHN_BROKER.add(authn_context_class_ref(req_authn_context), "")
        return AUTHN_BROKER.get_authn_by_accr(req_authn_context)

    def build_authn_response(self, user, authn, resp_args):
        name_id_formats = [resp_args.get('name_id_policy').format] or self.IDP.config.getattr("name_id_format", "idp") or [NAMEID_FORMAT_UNSPECIFIED]
        authn_resp = self.IDP.create_authn_response(
            authn=authn,
            identity=self.get_identity(user),
            userid=self.processor.get_user_id(user),
            name_id=NameID(format=name_id_formats[0], sp_name_qualifier=self.sp['id'], text=self.processor.get_user_id(user)),
            sign_response=self.IDP.config.getattr("sign_response", "idp") or False,
            sign_assertion=self.IDP.config.getattr("sign_assertion", "idp") or False,
            **resp_args)
        return authn_resp

    def create_html_response(self, request, binding, authn_resp, destination, relay_state):
        if binding == BINDING_HTTP_POST:
            context = {
                "acs_url": destination,
                "saml_response": base64.b64encode(authn_resp.encode()).decode(),
                "relay_state": relay_state,
            }
            html_response = render_to_string("djangosaml2idp/login.html", context=context, request=request)
        else:
            http_args = self.IDP.apply_binding(
                binding=binding,
                msg_str=authn_resp,
                destination=destination,
                relay_state=relay_state,
                response=True)

            logger.debug('http args are: %s' % http_args)
            html_response = http_args['data']

        return html_response

    def render_response(self, request, html_response):
        """ Return either as redirect to MultiFactorView or as html with self-submitting form.
        """
        if self.processor.enable_multifactor(request.user):
            # Store http_args in session for after multi factor is complete
            request.session['saml_data'] = html_response
            logger.debug("Redirecting to process_multi_factor")
            return HttpResponseRedirect(reverse('saml_multi_factor'))
        logger.debug("Performing SAML redirect")
        return HttpResponse(html_response)


@method_decorator(never_cache, name='dispatch')
class LoginProcessView(LoginRequiredMixin, IdPHandlerViewMixin, View):
    """ View which processes the actual SAML request and returns a self-submitting form with the SAML response.
        The login_required decorator ensures the user authenticates first on the IdP using 'normal' ways.
    """

    def get(self, request, *args, **kwargs):
        binding = request.session.get('Binding', BINDING_HTTP_POST)

        # Parse incoming request
        try:
            req_info = self.IDP.parse_authn_request(request.session['SAMLRequest'], binding)
        except Exception as excp:
            return self.handle_error(request, exception=excp)
        # Signed request for HTTP-REDIRECT
        if "SigAlg" in request.session and "Signature" in request.session:
            _certs = self.IDP.metadata.certs(req_info.message.issuer.text, "any", "signing")
            verified_ok = False
            for cert in _certs:
                # TODO implement
                # if verify_redirect_signature(_info, self.IDP.sec.sec_backend, cert):
                #    verified_ok = True
                #    break
                pass
            if not verified_ok:
                return self.handle_error(request, extra_message="Message signature verification failure", status=400)

        # Gather response arguments
        try:
            resp_args = self.IDP.response_args(req_info.message)
        except (UnknownPrincipal, UnsupportedBinding) as excp:
            return self.handle_error(request, exception=excp, status=400)

        try:
            self.set_sp(resp_args['sp_entity_id'])
            self.set_processor()
        except (KeyError, ImproperlyConfigured) as excp:
            return self.handle_error(request, exception=excp, status=400)

        # Check if user has access to the service of this SP
        if not self.processor.has_access(request):
            return self.handle_error(request, exception=PermissionDenied("You do not have access to this resource"), status=403)

        # Construct SamlResponse message
        try:
            authn_resp = self.build_authn_response(request.user, self.get_authn(), resp_args)
        except Exception as excp:
            return self.handle_error(request, exception=excp, status=500)

        html_response = self.create_html_response(
            request,
            binding=resp_args['binding'],
            authn_resp=authn_resp,
            destination=resp_args['destination'],
            relay_state=request.session['RelayState'])
        return self.render_response(request, html_response)


@method_decorator(never_cache, name='dispatch')
class SSOInitView(LoginRequiredMixin, IdPHandlerViewMixin, View):

    def post(self, request, *args, **kwargs):
        return self.get(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        passed_data = request.POST if request.method == 'POST' else request.GET

        # get sp information from the parameters
        try:
            self.set_sp(passed_data['sp'])
            self.set_processor()
        except (KeyError, ImproperlyConfigured) as excp:
            return self.handle_error(request, exception=excp, status=400)

        binding_out, destination = self.IDP.pick_binding(
            service="assertion_consumer_service",
            entity_id=self.sp['id'])

        # Check if user has access to the service of this SP
        if not self.processor.has_access(request):
            return self.handle_error(request, exception=PermissionDenied("You do not have access to this resource"), status=403)

        # Adding a few things that would have been added if this were SP Initiated
        passed_data['destination'] = destination
        passed_data['in_response_to'] = "IdP_Initiated_Login"
        passed_data['sp_entity_id'] = self.sp['id']

        # Construct SamlResponse messages
        try:
            authn_resp = self.build_authn_response(request.user, self.get_authn(), passed_data)
        except Exception as excp:
            return self.handle_error(request, exception=excp, status=500)

        html_response = self.create_html_response(request, binding_out, authn_resp, destination, passed_data['RelayState'])
        return self.render_response(request, html_response)


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
