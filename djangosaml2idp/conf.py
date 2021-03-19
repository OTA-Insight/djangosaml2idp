import copy
from typing import Callable, Optional, Union

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpRequest
from django.utils.module_loading import import_string


def get_callable(path: Union[Callable, str]) -> Callable:
    """ Import the function at a given path and return it
    """
    if callable(path):
        return path

    try:
        config_loader = import_string(path)
    except ImportError as e:
        raise ImproperlyConfigured(f'Error importing SAML config loader {path}: "{e}"')

    if not callable(config_loader):
        raise ImproperlyConfigured("SAML config loader must be a callable object.")

    return config_loader


def get_config(config_loader_path: Optional[Union[Callable, str]] = None, request: Optional[HttpRequest] = None) -> dict:
    """ Load a config_loader function if necessary, and call that function with the request as argument.
        If the config_loader_path is a callable instead of a string, no importing is necessary and it will be used directly.
        Return the resulting SPConfig.
    """
    static_config = copy.deepcopy(settings.SAML_IDP_CONFIG)

    if config_loader_path is None:
        return static_config or {}
    else:
        return get_callable(config_loader_path)(static_config, request)
