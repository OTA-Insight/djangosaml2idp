import copy

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.utils.translation import gettext as _
from saml2.config import IdPConfig
from saml2.metadata import entity_descriptor
from saml2.server import Server


class IDP:
    """ Access point for the IDP Server instance
    """
    _server_instance: Server = None

    @classmethod
    def construct_metadata(cls) -> dict:
        """ Get the config including the metadata for all the configured service providers. """
        from .models import ServiceProvider
        idp_config = copy.deepcopy(settings.SAML_IDP_CONFIG)
        if idp_config:
            idp_config['metadata'] = {  # type: ignore
                'local': [sp.metadata_path() for sp in ServiceProvider.objects.filter(active=True)],
            }
        return idp_config

    @classmethod
    def load(cls, force_refresh: bool = False) -> Server:
        """ Instantiate a IDP Server instance based on the config defined in the SAML_IDP_CONFIG settings.
            Throws an ImproperlyConfigured exception if it could not do so for any reason.
        """
        if cls._server_instance is None or force_refresh:
            conf = IdPConfig()
            md = cls.construct_metadata()
            try:
                conf.load(md)
                cls._server_instance = Server(config=conf)
            except Exception as e:
                raise ImproperlyConfigured(_('Could not instantiate an IDP based on the SAML_IDP_CONFIG settings and configured ServiceProviders: {}').format(str(e)))
        return cls._server_instance

    @classmethod
    def metadata(cls) -> str:
        """ Get the IDP metadata as a string. """
        conf = IdPConfig()
        try:
            conf.load(cls.construct_metadata())
            metadata = entity_descriptor(conf)
        except Exception as e:
            raise ImproperlyConfigured(_('Could not instantiate IDP metadata based on the SAML_IDP_CONFIG settings and configured ServiceProviders: {}').format(str(e)))
        return str(metadata)
