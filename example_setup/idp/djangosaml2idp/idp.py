from saml2.config import IdPConfig
import copy
from django.conf import settings
from saml2.server import Server
from django.core.exceptions import (ImproperlyConfigured)
from django.utils.translation import gettext as _
from django.utils.functional import cached_property


class IDP:
    """ Access point for the IDP Server instance
    """

    @cached_property
    @classmethod
    def load(cls):
        """ Instantiate a IDP Server instance based on the config defined in the SAML_IDP_CONFIG settings.
            Throws an ImproperlyConfigured exception if it could not do so for any reason.
        """
        conf = IdPConfig()
        try:
            conf.load(copy.deepcopy(settings.SAML_IDP_CONFIG))
            return Server(config=conf)
        except Exception as e:
            raise ImproperlyConfigured(_('Could not instantiate an IDP based on the SAML_IDP_CONFIG settings: {}').format(str(e)))
