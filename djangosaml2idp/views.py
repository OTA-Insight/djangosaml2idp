import base64
import copy
import logging

from django.conf import settings
from django.contrib.auth import logout
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import (ImproperlyConfigured, PermissionDenied,
                                    ValidationError)
from django.http import HttpResponse, HttpResponseRedirect
from django.template.exceptions import (TemplateDoesNotExist,
                                        TemplateSyntaxError)
from django.template.loader import get_template
from django.urls import reverse
from django.utils.datastructures import MultiValueDictKeyError
from django.utils.decorators import method_decorator
from django.utils.module_loading import import_string
from django.utils.translation import gettext as _
from django.views import View
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT, xmldsig
from saml2.authn_context import PASSWORD, AuthnBroker, authn_context_class_ref
from saml2.config import IdPConfig
from saml2.ident import NameID
from saml2.metadata import entity_descriptor
from saml2.saml import NAMEID_FORMAT_UNSPECIFIED
from saml2.server import Server
from six import text_type

from .error_views import error_cbv
from .processors import BaseProcessor
from .utils import repr_saml

logger = logging.getLogger(__name__)

try:
    idp_sp_config = settings.SAML_IDP_SPCONFIG
except AttributeError:
    raise ImproperlyConfigured(_("SAML_IDP_SPCONFIG not defined in settings."))


def store_params_in_session(request):
    """ Gathers the SAML parameters from the HTTP request and store them in the session
    """
    if request.method == 'POST':
        # future TODO: parse also SOAP and PAOS format from POST
        passed_data = request.POST
        binding = BINDING_HTTP_POST
    else:
        passed_data = request.GET
        binding = BINDING_HTTP_REDIRECT

    try:
        saml_request = passed_data['SAMLRequest']
    except (KeyError, MultiValueDictKeyError) as e:
        raise ValidationError(_('not a valid SAMLRequest: {}').format(repr(e)))

    request.session['Binding'] = binding
    request.session['SAMLRequest'] = saml_request
    request.session['RelayState'] = passed_data.get('RelayState', '')


@never_cache
@csrf_exempt
@require_http_methods(["GET", "POST"])
def sso_entry(request, *args, **kwargs):
    """ Entrypoint view for SSO. Store the saml info in the request session
        and redirects to the login_process view.
    """
    try:
        store_params_in_session(request)
    except ValidationError as e:
        return error_cbv.handle_error(request, e, status_code=400)

    logger.debug("SSO requested to IDP with binding {}".format(request.session['Binding']))
    logger.debug("SAML request [\n{}]".format(repr_saml(request.session['SAMLRequest'], b64=True)))

    return HttpResponseRedirect(reverse('djangosaml2idp:saml_login_process'))


class IdPHandlerViewMixin:
    """ Contains some methods used by multiple views """

    def dispatch(self, request, *args, **kwargs):
        """ Construct IDP server with config from settings dict
        """
        conf = IdPConfig()
        try:
            conf.load(copy.deepcopy(settings.SAML_IDP_CONFIG))
            self.IDP = Server(config=conf)
        except Exception as e:
            return error_cbv.handle_error(request, exception=e)
        return super().dispatch(request, *args, **kwargs)

    def get_sp_config(self, sp_entity_id):
        """ Get a dict with the configuration for a SP according to the SAML_IDP_SPCONFIG settings.
            Raises an exception if no SP matching the given entity id can be found.
        """
        d = {'id': sp_entity_id}
        try:
            d['config'] = settings.SAML_IDP_SPCONFIG[sp_entity_id]
        except KeyError:
            raise ImproperlyConfigured(_("No config for SP {} defined in SAML_IDP_SPCONFIG").format(sp_entity_id))
        return d

    def get_processor(self, sp_entity_id: str, processor_class_path: str) -> BaseProcessor:
        """ Instantiate user-specified processor or default to an all-access base processor.
            Raises an exception if the processor class can not be found or initialized.
        """
        if processor_class_path:
            try:
                processor_cls = import_string(processor_class_path)
            except ImportError as e:
                msg = _("Failed to import processor class {}").format(processor_class_path)
                logger.error(msg, exc_info=True)
                raise ImproperlyConfigured(msg) from e
        else:
            processor_cls = BaseProcessor

        try:
            processor_instance = processor_cls(sp_entity_id)
        except Exception as e:
            msg = _("Failed to instantiate processor: {} - {}").format(processor_cls, e)
            logger.error(msg, exc_info=True)
            raise
        return processor_instance

    def verify_request_signature(self, req_info):
        """ Signature verification for authn request signature_check is at
            saml2.sigver.SecurityContext.correctly_signed_authn_request
        """
        # TODO: Add unit tests for this
        if not req_info.signature_check(req_info.xmlstr):
            raise ValueError(_("Message signature verification failure"))

    def check_access(self, processor, request):
        """ Check if user has access to the service of this SP. Raises a PermissionDenied exception if not.
        """
        if not processor.has_access(request):
            raise PermissionDenied(_("You do not have access to this resource"))

    def get_authn(self, req_info=None):
        req_authn_context = req_info.message.requested_authn_context if req_info else PASSWORD
        broker = AuthnBroker()
        broker.add(authn_context_class_ref(req_authn_context), "")
        return broker.get_authn_by_accr(req_authn_context)

    def build_authn_response(self, user, authn, resp_args, processor: BaseProcessor, sp_config: dict):
        """ pysaml2 server.Server.create_authn_response wrapper
        """
        policy = resp_args.get('name_id_policy', None)
        if policy is None:
            sp_config['name_id_format'] = NAMEID_FORMAT_UNSPECIFIED
        else:
            sp_config['name_id_format'] = policy.format

        idp_name_id_format_list = self.IDP.config.getattr("name_id_format", "idp") or [NAMEID_FORMAT_UNSPECIFIED]

        if sp_config['name_id_format'] not in idp_name_id_format_list:
            raise ImproperlyConfigured(_('SP requested a name_id_format that is not supported in the IDP'))

        user_id = processor.get_user_id(user, sp_config, self.IDP.config)
        name_id = NameID(format=sp_config['name_id_format'], sp_name_qualifier=sp_config['id'], text=user_id)

        authn_resp = self.IDP.create_authn_response(
            authn=authn,
            identity=processor.create_identity(user, sp_config['config'].get('attribute_mapping')),
            name_id=name_id,
            userid=user_id,
            sp_entity_id=sp_config['id'],
            # Signing
            sign_response=sp_config['config'].get("sign_response") or self.IDP.config.getattr("sign_response", "idp") or False,
            sign_assertion=sp_config['config'].get("sign_assertion") or self.IDP.config.getattr("sign_assertion", "idp") or False,
            sign_alg=sp_config['config'].get("signing_algorithm") or getattr(settings, "SAML_AUTHN_SIGN_ALG", xmldsig.SIG_RSA_SHA256),
            digest_alg=sp_config['config'].get("digest_algorithm") or getattr(settings, "SAML_AUTHN_DIGEST_ALG", xmldsig.DIGEST_SHA256),
            # Encryption
            encrypt_assertion=sp_config['config'].get('encrypt_saml_responses') or getattr(settings, 'SAML_ENCRYPT_AUTHN_RESPONSE', False),
            encrypted_advice_attributes=sp_config['config'].get('encrypt_saml_responses') or getattr(settings, 'SAML_ENCRYPT_AUTHN_RESPONSE', False),
            **resp_args
        )
        return authn_resp

    def render_login_html_to_string(self, context=None, request=None, using=None):
        """ Render the html response for the login action. Can be using a custom html template if set on the view. """
        default_login_template_name = 'djangosaml2idp/login.html'
        custom_login_template_name = getattr(self, 'login_html_template', None)
        if custom_login_template_name:
            try:
                template = get_template(custom_login_template_name, using=using)
            except (TemplateDoesNotExist, TemplateSyntaxError) as e:
                logger.error('Specified template {} cannot be used due to: {}. Falling back to default login template'.format(custom_login_template_name, str(e)))
                template = get_template(default_login_template_name, using=using)
        else:
            template = get_template(default_login_template_name, using=using)
        return template.render(context, request)

    def create_html_response(self, request, binding, authn_resp, destination, relay_state):
        """ Login form for SSO
        """
        if binding == BINDING_HTTP_POST:
            context = {
                "acs_url": destination,
                "saml_response": base64.b64encode(str(authn_resp).encode()).decode(),
                "relay_state": relay_state,
            }
            html_response = {
                "data": self.render_login_html_to_string(context=context, request=request),
                "type": "POST",
            }
        else:
            http_args = self.IDP.apply_binding(
                binding=binding,
                msg_str=authn_resp,
                destination=destination,
                relay_state=relay_state,
                response=True)

            logger.debug('http args are: %s' % http_args)
            html_response = {
                "data": http_args['headers'][0][1],
                "type": "REDIRECT",
            }
        return html_response

    def render_response(self, request, html_response, processor: BaseProcessor = None):
        """ Return either a response as redirect to MultiFactorView or as html with self-submitting form to log in.
        """
        if not processor:
            # In case of SLO, where processor isn't relevant
            if html_response['type'] == 'POST':
                return HttpResponse(html_response['data'])
            else:
                return HttpResponseRedirect(html_response['data'])

        request.session['saml_data'] = html_response

        if processor.enable_multifactor(request.user):
            logger.debug("Redirecting to process_multi_factor")
            return HttpResponseRedirect(reverse('djangosaml2idp:saml_multi_factor'))

        # No multifactor
        logger.debug("Performing SAML redirect")
        if html_response['type'] == 'POST':
            return HttpResponse(html_response['data'])
        else:
            return HttpResponseRedirect(html_response['data'])


@method_decorator(never_cache, name='dispatch')
class LoginProcessView(LoginRequiredMixin, IdPHandlerViewMixin, View):
    """ View which processes the actual SAML request and returns a self-submitting form with the SAML response.
        The login_required decorator ensures the user authenticates first on the IdP using 'normal' ways.
    """

    def get(self, request, *args, **kwargs):
        binding = request.session.get('Binding', BINDING_HTTP_POST)

        # TODO: would it be better to store SAML info in request objects?
        # AuthBackend takes request obj as argument...
        try:
            # Parse incoming request
            req_info = self.IDP.parse_authn_request(request.session['SAMLRequest'],
                                                    binding)
            # check SAML request signature
            self.verify_request_signature(req_info)
            # Compile Response Arguments
            resp_args = self.IDP.response_args(req_info.message)
            # Set SP and Processor
            sp_entity_id = resp_args.pop('sp_entity_id')
            sp_config = self.get_sp_config(sp_entity_id)
            processor = self.get_processor(sp_entity_id, sp_config['config'].get('processor', ''))
            # Check if user has access
            try:
                # Check if user has access to SP
                self.check_access(processor, request)
            except PermissionDenied as excp:
                return error_cbv.handle_error(request, exception=excp, status_code=403)
            # Construct SamlResponse message
            authn_resp = self.build_authn_response(request.user, self.get_authn(), resp_args, processor, sp_config)
        except Exception as e:
            return error_cbv.handle_error(request, exception=e, status_code=500)

        html_response = self.create_html_response(
            request,
            binding=resp_args['binding'],
            authn_resp=authn_resp,
            destination=resp_args['destination'],
            relay_state=request.session['RelayState'])

        logger.debug("--- SAML Authn Response [\n{}] ---".format(repr_saml(str(authn_resp))))
        return self.render_response(request, html_response, processor)


@method_decorator(never_cache, name='dispatch')
class SSOInitView(LoginRequiredMixin, IdPHandlerViewMixin, View):
    """ View used for IDP initialized login, doesn't handle any SAML authn request
    """

    def post(self, request, *args, **kwargs):
        return self.get(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        passed_data = request.POST or request.GET
        passed_data = passed_data.copy().dict()

        try:
            # get sp information from the parameters
            sp_entity_id = passed_data['sp']
            sp_config = self.get_sp_config(sp_entity_id)
            processor = self.get_processor(sp_entity_id, sp_config['config'].get('processor', ''))
        except (KeyError, ImproperlyConfigured) as excp:
            return error_cbv.handle_error(request, exception=excp, status_code=400)

        try:
            # Check if user has access to SP
            self.check_access(processor, request)
        except PermissionDenied as excp:
            return error_cbv.handle_error(request, exception=excp, status_code=403)

        binding_out, destination = self.IDP.pick_binding(
            service="assertion_consumer_service",
            entity_id=sp_entity_id)

        # Adding a few things that would have been added if this were SP Initiated
        passed_data['destination'] = destination
        passed_data['in_response_to'] = "IdP_Initiated_Login"

        # Construct SamlResponse messages
        authn_resp = self.build_authn_response(request.user, self.get_authn(), passed_data, processor, sp_config)

        html_response = self.create_html_response(request, binding_out, authn_resp, destination, passed_data.get('RelayState', ""))
        return self.render_response(request, html_response, processor)


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
            html_response = request.session['saml_data']
            if html_response['type'] == 'POST':
                return HttpResponse(html_response['data'])
            else:
                return HttpResponseRedirect(html_response['data'])
        logger.debug(_("MultiFactor failed; %s will not be able to log in") % request.user)
        logout(request)
        raise PermissionDenied(_("MultiFactor authentication factor failed"))


@method_decorator([never_cache, csrf_exempt], name='dispatch')
class LogoutProcessView(LoginRequiredMixin, IdPHandlerViewMixin, View):
    """ View which processes the actual SAML Single Logout request
        The login_required decorator ensures the user authenticates first on the IdP using 'normal' way.
    """
    __service_name = 'Single LogOut'

    def post(self, request, *args, **kwargs):
        return self.get(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        logger.info("--- {} Service ---".format(self.__service_name))
        # do not assign a variable that overwrite request object, if it will fail the return with HttpResponseBadRequest trows naturally
        store_params_in_session(request)
        binding = request.session['Binding']
        relay_state = request.session['RelayState']
        logger.debug("--- {} requested [\n{}] to IDP ---".format(self.__service_name, binding))

        # adapted from pysaml2 examples/idp2/idp_uwsgi.py
        try:
            req_info = self.IDP.parse_logout_request(request.session['SAMLRequest'], binding)
        except Exception as excp:
            expc_msg = "{} Bad request: {}".format(self.__service_name, excp)
            logger.error(expc_msg)
            return error_cbv.handle_error(request, exception=expc_msg, status_code=400)

        logger.info("{} - local identifier: {} from {}".format(self.__service_name, req_info.message.name_id.text, req_info.message.name_id.sp_name_qualifier))
        logger.debug("--- {} SAML request [\n{}] ---".format(self.__service_name, repr_saml(req_info.xmlstr, b64=False)))

        # TODO
        # check SAML request signature
        self.verify_request_signature(req_info)
        resp = self.IDP.create_logout_response(req_info.message, [binding])

        '''
        # TODO: SOAP
        # if binding == BINDING_SOAP:
            # destination = ""
            # response = False
        # else:
            # binding, destination = IDP.pick_binding(
                # "single_logout_service", [binding], "spsso", req_info
            # )
            # response = True
        # END TODO SOAP'''

        try:
            # hinfo returns request or response, it depends by request arg
            hinfo = self.IDP.apply_binding(binding, resp.__str__(), resp.destination, relay_state, response=True)
        except Exception as excp:
            logger.error("ServiceError: %s", excp)
            return error_cbv.handle_error(request, exception=excp, status=400)

        logger.debug("--- {} Response [\n{}] ---".format(self.__service_name, repr_saml(resp.__str__().encode())))
        logger.debug("--- binding: {} destination:{} relay_state:{} ---".format(binding, resp.destination, relay_state))

        # TODO: double check username session and saml login request
        # logout user from IDP
        logout(request)

        if hinfo['method'] == 'GET':
            return HttpResponseRedirect(hinfo['headers'][0][1])
        else:
            html_response = self.create_html_response(
                request,
                binding=binding,
                authn_resp=resp.__str__(),
                destination=resp.destination,
                relay_state=relay_state)
        return self.render_response(request, html_response, None)


@never_cache
def get_multifactor(request):
    if hasattr(settings, "SAML_IDP_MULTIFACTOR_VIEW"):
        multifactor_class = import_string(getattr(settings, "SAML_IDP_MULTIFACTOR_VIEW"))
    else:
        multifactor_class = ProcessMultiFactorView
    return multifactor_class.as_view()(request)


@never_cache
def metadata(request):
    """ Returns an XML with the SAML 2.0 metadata for this Idp.
        The metadata is constructed on-the-fly based on the config dict in the django settings.
    """
    conf = IdPConfig()
    conf.load(copy.deepcopy(settings.SAML_IDP_CONFIG))
    metadata = entity_descriptor(conf)
    return HttpResponse(content=text_type(metadata).encode('utf-8'), content_type="text/xml; charset=utf8")
