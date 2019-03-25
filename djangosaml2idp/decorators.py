import logging

from django.http import HttpResponseBadRequest
from django.utils.datastructures import MultiValueDictKeyError
from django.utils.translation import gettext as _
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT

from .utils import repr_saml

logger = logging.getLogger(__name__)


def store_params_in_session(request):
    """ Entrypoint view for SSO. Gathers the parameters from the
        HTTP request and stores them in the session

        It do not return anything because request come as pointer
    """
    if request.method == 'POST':
        # future TODO: parse also SOAP and PAOS format from POST
        passed_data = request.POST
        binding = BINDING_HTTP_POST
    else:
        passed_data = request.GET
        binding = BINDING_HTTP_REDIRECT

    request.session['Binding'] = binding
    try:
        msg = "--- SAML request [\n{}] ---"
        logger.debug(msg.format(repr_saml(passed_data['SAMLRequest'],
                                b64=True)))
        request.session['SAMLRequest'] = passed_data['SAMLRequest']
    except (KeyError, MultiValueDictKeyError) as e:
        msg = _('not a valid SAMLRequest: {}').format(e)
        return HttpResponseBadRequest(msg)
    request.session['RelayState'] = passed_data.get('RelayState', '')


def store_params_in_session_func(func_to_decorate):
    """ store_params_in_session as a funcion decorator
    """
    def new_func(*original_args, **original_kwargs):
        request = original_args[0]
        try:
            store_params_in_session(request)
            return func_to_decorate(*original_args, **original_kwargs)
        except Exception as e:
            msg = _('not a valid SAMLRequest: {}').format(e)
            return HttpResponseBadRequest(msg)
    return new_func
