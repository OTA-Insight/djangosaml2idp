import copy

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.utils.module_loading import import_string
from django.utils.translation import gettext as _
from saml2.config import IdPConfig
from saml2.metadata import entity_descriptor
from saml2.server import Server


class IDP(Server):
    """ Access point for the IDP Server instance
    """
    
    def __init__(self, conf: dict):
        idp_conf = IdPConfig()
        try:
            md = self.construct_metadata(conf)
            idp_conf.load(md)
        except Exception as e:
            raise ImproperlyConfigured(_('Could not instantiate an IDP based on the SAML_IDP_CONFIG settings and configured ServiceProviders: {}').format(str(e)))
        super().__init__(config=idp_conf)

    def construct_metadata(self, conf) -> dict:
        """ Get the config including the metadata for all the configured service providers. """
        from .models import ServiceProvider
        if conf:
            conf['metadata'] = {  # type: ignore
                'local': [sp.metadata_path() for sp in ServiceProvider.objects.filter(active=True)],
            }
        return conf

    def get_metadata(self) -> str:
        """ Get the IDP metadata as a string. """
        try:
            metadata = entity_descriptor(self.config)
        except Exception as e:
            raise ImproperlyConfigured(_('Could not instantiate IDP metadata: {}').format(str(e)))
        return str(metadata)
