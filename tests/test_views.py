import pytest

from django.contrib.auth import get_user_model

from djangosaml2idp.views import IdPHandlerViewMixin

from djangosaml2idp.processors import BaseProcessor


User = get_user_model()


class CustomProcessor(BaseProcessor):
    pass


class TestIdPHandlerViewMixin:
    def test_get_identity_provides_extra_config(self):
        IdPHandlerViewMixin()

    def test_get_processor_errors_if_processor_cannot_be_loaded(self):
        sp_config = {
            'processor': 'this.does.not.exist'
        }

        with pytest.raises(Exception):
            IdPHandlerViewMixin().get_processor('entity_id', sp_config)

    def test_get_processor_defaults_to_base_processor(self):
        sp_config = {
        }

        assert isinstance(IdPHandlerViewMixin().get_processor('entity_id', sp_config), BaseProcessor)

    def test_get_processor_loads_custom_processor(self):
        sp_config = {
            'processor': 'tests.test_views.CustomProcessor'
        }

        assert isinstance(IdPHandlerViewMixin().get_processor('entity_id', sp_config), CustomProcessor)


class TestIdpInitiatedFlow:
    pass


class TestMetadata:
    pass


class LoginFlow:
    def test_requires_authentication(self):
        """test redriect to settings.LOGIN_VIEW"""
        pass
