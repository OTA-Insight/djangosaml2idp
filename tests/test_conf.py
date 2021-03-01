import pytest
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpRequest

from djangosaml2idp.conf import get_callable, get_config
from djangosaml2idp.utils import repr_saml
from .settings import SAML_IDP_CONFIG

class TestConf:
    def test_get_callable_callable(self):
        func_callable = lambda x: x
        assert get_callable(func_callable) == func_callable

    def test_get_callable_path(self):
        assert get_callable('djangosaml2idp.utils.repr_saml') == repr_saml

    def test_get_callable_path_unokwn(self):
        with pytest.raises(ImproperlyConfigured):
            get_callable('some.where.else')
            
    def test_get_callable_path_not_callable(self):
        with pytest.raises(ImproperlyConfigured):
            get_callable('djangosaml2idp.urls.app_name')
            
    def test_get_config_static_conf(self):
        assert get_config() == SAML_IDP_CONFIG
        
    def test_get_config_static_conf_empty(self, settings):
        settings.SAML_IDP_CONFIG = None
        assert get_config() == {}
        
    def test_get_config(self):
        request = HttpRequest()
        return_value = "xxx"
        def loader(c, r):
            called = True
            assert c == SAML_IDP_CONFIG
            assert r == request
            return return_value

        assert get_config(loader, request) == return_value
