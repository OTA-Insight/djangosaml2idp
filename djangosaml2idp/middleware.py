from django.conf import settings
from django.utils.deprecation import MiddlewareMixin

from .utils import get_root_cookie_domain


class HintCookieMiddleWare(MiddlewareMixin):
    """
    Middleware to set SAML SSO user hint cookie
    """
    def process_response(self, request, response):
        # In case someone is visting one of our URL without a trailing slash then request.user
        # will raise an attribute error. Details: http://stackoverflow.com/a/21100938/846892
        if not hasattr(request, 'user'):
            return response

        hint_cookie_name = settings.SAML_HINT_COOKIE_NAME
        if request.user.is_authenticated and not request.COOKIES.get(hint_cookie_name):
            response.set_cookie(hint_cookie_name, 1, domain=get_root_cookie_domain(request),
                                max_age=31536000, path='/', secure=True, httponly=True)

        elif not request.user.is_authenticated and request.COOKIES.get(hint_cookie_name):
            response.delete_cookie(hint_cookie_name, domain=get_root_cookie_domain(request))

        return response
