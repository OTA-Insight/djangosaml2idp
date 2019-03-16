import pytest

from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpRequest

from djangosaml2idp.views import IdPHandlerViewMixin
from djangosaml2idp.processors import BaseProcessor


User = get_user_model()


class CustomProcessor(BaseProcessor):
    pass


class TestIdPHandlerViewMixin:
    def test_dispatch_fails_if_IDP_config_undefined_in_settings(self, settings):
        del settings.SAML_IDP_CONF

        with pytest.raises(Exception):
            IdPHandlerViewMixin().dispatch(HttpRequest())

    def test_set_sp_errors_if_sp_not_defined(self):
        mixin = IdPHandlerViewMixin()

        with pytest.raises(ImproperlyConfigured):
            mixin.set_sp('this_sp_does_not_exist')

    def test_set_sp_works_if_sp_defined(self, settings):
        mixin = IdPHandlerViewMixin()
        mixin.set_sp('test_generic_sp')

        assert mixin.sp == {
            'id': 'test_generic_sp',
            'config': settings.SAML_IDP_SPCONFIG['test_generic_sp']
        }

    def test_set_processor_errors_if_processor_cannot_be_loaded(self):
        mixin = IdPHandlerViewMixin()
        mixin.set_sp('test_sp_with_bad_processor')

        with pytest.raises(Exception):
            mixin.set_processor()

    def test_set_processor_defaults_to_base_processor(self):
        mixin = IdPHandlerViewMixin()
        mixin.set_sp('test_sp_with_no_processor')
        mixin.set_processor()

        assert isinstance(mixin.processor, BaseProcessor)

    def test_get_processor_loads_custom_processor(self):
        mixin = IdPHandlerViewMixin()
        mixin.set_sp('test_sp_with_custom_processor')
        mixin.set_processor()

        assert isinstance(mixin.processor, CustomProcessor)

    def test_get_authn_returns_correctly_when_no_req_info(self):
        mixin = IdPHandlerViewMixin()

        assert mixin.get_authn() == {
            'authn_auth': '',
            'class_ref': 'urn:oasis:names:tc:SAML:2.0:ac:classes:Password',
            'level': 0,
            'method': ''
        }


class TestIdpInitiatedFlow:
    pass


class TestMetadata:
    pass


class LoginFlow:
    def test_requires_authentication(self):
        """test redriect to settings.LOGIN_VIEW"""
        pass
