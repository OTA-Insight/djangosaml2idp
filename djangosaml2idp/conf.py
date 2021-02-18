# Copyright (C) 2010-2012 Yaco Sistemas (http://www.yaco.es)
# Copyright (C) 2009 Lorenzo Gil Sanchez <lorenzo.gil.sanchez@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#            http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import copy
from typing import Callable, Optional, Union

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpRequest
from django.utils.module_loading import import_string
from saml2.config import IdPConfig


def get_config_loader(path: str) -> Callable:
    """ Import the function at a given path and return it
    """
    try:
        config_loader = import_string(path)
    except ImportError as e:
        raise ImproperlyConfigured(f'Error importing SAML config loader {path}: "{e}"')

    if not callable(config_loader):
        raise ImproperlyConfigured("SAML config loader must be a callable object.")

    return config_loader


def get_config(config_loader_path: Optional[Union[Callable, str]] = None, request: Optional[HttpRequest] = None) -> IdPConfig:
    """ Load a config_loader function if necessary, and call that function with the request as argument.
        If the config_loader_path is a callable instead of a string, no importing is necessary and it will be used directly.
        Return the resulting SPConfig.
    """
    static_config = copy.deepcopy(settings.SAML_IDP_CONFIG)
    config_loader_path = config_loader_path or getattr(settings, 'SAML_IDP_CONFIG_LOADER', None)
    
    if config_loader_path is None:
        return static_config
    else:
        if callable(config_loader_path):
            config_loader = config_loader_path
        else:
            config_loader = get_config_loader(config_loader_path)
        return config_loader(static_config, request)

