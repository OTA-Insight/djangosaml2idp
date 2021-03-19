from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpRequest
from django.utils.translation import gettext as _
from saml2.config import IdPConfig
from saml2.metadata import entity_descriptor
from saml2.server import Server
from typing import Callable, Dict, Optional, Union

from .conf import get_callable, get_config


class IDP:
    """ Access point for the IDP Server instance
    """
    _server_instances: Dict[str, Server] = {}

    @classmethod
    def construct_metadata(cls, idp_conf: dict, request: Optional[HttpRequest] = None, with_local_sp: bool = True) -> IdPConfig:
        """ Get the config including the metadata for all the configured service providers. """
        conf = IdPConfig()

        from .models import ServiceProvider
        sp_queryset = ServiceProvider.objects.none()
        if with_local_sp:
            sp_queryset = ServiceProvider.objects.filter(active=True)
            if getattr(settings, "SAML_IDP_FILTER_SP_QUERYSET", None) is not None:
                sp_queryset = get_callable(settings.SAML_IDP_FILTER_SP_QUERYSET)(sp_queryset, request)

        idp_conf['metadata'] = {  # type: ignore
            'local': (
                [sp.metadata_path() for sp in sp_queryset]
                if with_local_sp else []
            ),
        }
        try:
            conf.load(idp_conf)
        except Exception as e:
            raise ImproperlyConfigured(_('Could not instantiate an IDP based on the SAML_IDP_CONFIG settings and configured ServiceProviders: {}').format(str(e)))
        return conf

    @classmethod
    def load(cls, request: Optional[HttpRequest] = None, config_loader_path: Optional[Union[Callable, str]] = None) -> Server:
        idp_conf = get_config(config_loader_path, request)
        if "entityid" not in idp_conf:
            raise ImproperlyConfigured('The configuration must contain an entityid')
        entity_id = idp_conf["entityid"]

        if entity_id not in cls._server_instances:
            # actually initialize the IdP server and cache it
            conf = cls.construct_metadata(idp_conf, request)
            cls._server_instances[entity_id] = Server(config=conf)

        return cls._server_instances[entity_id]

    @classmethod
    def flush(cls):
        cls._server_instances = {}

    @classmethod
    def metadata(cls, request: Optional[HttpRequest] = None, config_loader_path: Optional[Union[Callable, str]] = None) -> str:
        """ Get the IDP metadata as a string. """
        try:
            conf = cls.construct_metadata(get_config(config_loader_path, request), request, with_local_sp=False)
            metadata = entity_descriptor(conf)
        except Exception as e:
            raise ImproperlyConfigured(_('Could not instantiate IDP metadata: {}').format(str(e)))
        return str(metadata)
