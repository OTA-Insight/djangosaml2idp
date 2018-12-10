import pytest

from django.contrib.auth import get_user_model

from djangosaml2idp.views import IdPHandlerViewMixin

from djangosaml2idp.processors import BaseProcessor


User = get_user_model()


class CustomProcessor(BaseProcessor):
    pass


class TestIdPHandlerViewMixin:
    def test_get_identity_provides_extra_config(self):
        obj = IdPHandlerViewMixin()

    def test_extract_user_id_configure_by_user_class(self):

        user = User()
        user.USERNAME_FIELD = 'email'
        user.email = 'test_email'

        assert IdPHandlerViewMixin().extract_user_id(user) == 'test_email'

    def test_extract_user_id_configure_by_settings(self, settings):
        """Should use `settings.SAML_IDP_DJANGO_USERNAME_FIELD` to determine the user id field"""

        settings.SAML_IDP_DJANGO_USERNAME_FIELD = 'first_name'

        user = User()
        user.first_name = 'test_first_name'

        assert IdPHandlerViewMixin().extract_user_id(user) == 'test_first_name'

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
