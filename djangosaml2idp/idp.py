import copy

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.utils.translation import gettext as _
from saml2.config import IdPConfig
from saml2.metadata import entity_descriptor
from saml2.server import Server
from six import text_type


class IDP:
    """ Access point for the IDP Server instance
    """
    _server_instance = None

    @classmethod
    def load(cls):
        """ Instantiate a IDP Server instance based on the config defined in the SAML_IDP_CONFIG settings.
            Throws an ImproperlyConfigured exception if it could not do so for any reason.
        """
        if cls._server_instance is None:
            conf = IdPConfig()
            try:
                from .models import ServiceProvider
                idp_config_settings = copy.deepcopy(settings.SAML_IDP_CONFIG)
                idp_config_settings['metadata'] = {
                    'local': [sp.metadata_path for sp in ServiceProvider.objects.filter(active=True)],
                }
                conf.load(idp_config_settings)
                cls._server_instance = Server(config=conf)
            except Exception as e:
                raise ImproperlyConfigured(_('Could not instantiate an IDP based on the SAML_IDP_CONFIG settings: {}').format(str(e)))
        return cls._server_instance

    @classmethod
    def metadata(cls) -> str:
        conf = IdPConfig()
        conf.load(copy.deepcopy(settings.SAML_IDP_CONFIG))
        metadata = entity_descriptor(conf)
        return text_type(metadata)
