from typing import Callable, Dict, Optional, TypeVar, Union
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpRequest
from django.utils.translation import gettext as _
from saml2.config import IdPConfig
from saml2.metadata import entity_descriptor
from saml2.server import Server

from .conf import get_config

T = TypeVar('T', bound='IDP') 

class IDP(Server):
    """ Access point for the IDP Server instance
    """
    _server_instances: Dict[str, T] = {}

    @classmethod
    def load(cls, request: Optional[HttpRequest] = None, config_loader_path: Optional[Union[Callable, str]] = None) -> T:
        conf = get_config(config_loader_path, request)
        if "entityid" not in conf:
            raise ImproperlyConfigured(f'The configuration must contain an entityid')
        entity_id = conf["entityid"]
        
        if entity_id not in cls._server_instances:
            # actually initialize the IdP server and cache it
            from .models import ServiceProvider
            sp_queryset = ServiceProvider.objects.filter(active=True)
            if "filter_sp_queryset" in conf:
                sp_queryset = get_callable(conf["filter_sp_queryset"])(sp_queryset, request)
            cls._server_instances[entity_id] = cls(config=cls.construct_metadata(conf, sp_queryset))
        return cls._server_instances[entity_id]

    @classmethod
    def flush(cls):
        cls._server_instances = {}
    
    @classmethod
    def construct_metadata(cls, conf: dict, sp_queryset) -> dict:
        """ Get the config including the metadata for all the configured service providers. """
        idp_conf = IdPConfig()
        conf['metadata'] = {  # type: ignore
            'local': [sp.metadata_path() for sp in sp_queryset],
        }
        try:
            idp_conf.load(conf)
        except Exception as e:
            raise ImproperlyConfigured(_('Could not instantiate an IDP based on the SAML_IDP_CONFIG settings and configured ServiceProviders: {}').format(str(e)))
        return idp_conf

    def get_metadata(self) -> str:
        """ Get the IDP metadata as a string. """
        try:
            metadata = entity_descriptor(self.config)
        except Exception as e:
            raise ImproperlyConfigured(_('Could not instantiate IDP metadata: {}').format(str(e)))
        return str(metadata)
