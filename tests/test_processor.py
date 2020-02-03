import json

import pytest
from django.contrib.auth import get_user_model
from django.http import HttpRequest
from saml2.saml import NAMEID_FORMAT_UNSPECIFIED

from djangosaml2idp.idp import IDP
from djangosaml2idp.models import ServiceProvider
from djangosaml2idp.processors import BaseProcessor

User = get_user_model()


class TestBaseProcessor:

    def test_has_access_returns_true_by_default(self):
        request = HttpRequest()
        request.method = "GET"

        assert BaseProcessor('entity-id').has_access(request) is True

    def test_enable_multifactor_returns_false_by_default(self):
        user = User()

        assert BaseProcessor('entity-id').enable_multifactor(user) is False

    @pytest.mark.django_db
    def test_extract_user_id_default_to_username(self):
        user = User()
        user.username = 'test_username'

        service_provider = ServiceProvider(entity_id='entity-id')
        idp = IDP.load().config

        assert BaseProcessor('entity-id').get_user_id(user, NAMEID_FORMAT_UNSPECIFIED, service_provider, idp) == 'test_username'

    def test_extract_user_id_configure_by_settings(self, settings):
        """Should use `settings.SAML_IDP_DJANGO_USERNAME_FIELD` to determine the user id field"""

        settings.SAML_IDP_DJANGO_USERNAME_FIELD = 'first_name'

        user = User()
        user.first_name = 'test_first_name'

        service_provider = ServiceProvider(entity_id='entity-id')
        idp = IDP.load().config

        assert BaseProcessor('entity-id').get_user_id(user, NAMEID_FORMAT_UNSPECIFIED, service_provider, idp) == 'test_first_name'

    def test_extract_user_id_configure_on_service_provider(self):
        user = User()
        user.USERNAME_FIELD = 'email'
        user.email = 'test_email'

        service_provider = ServiceProvider(entity_id='entity-id', _nameid_field='email')
        idp = IDP.load().config

        assert BaseProcessor('entity-id').get_user_id(user, NAMEID_FORMAT_UNSPECIFIED, service_provider, idp) == 'test_email'

    def test_extract_user_id_from_sp_config_if_method(self):

        def random_method(self):
            return "test method result"

        User.random_method = random_method

        user = User()

        service_provider = ServiceProvider(entity_id='entity-id', _nameid_field='random_method')
        idp = IDP.load().config

        assert BaseProcessor('entity-id').get_user_id(user, NAMEID_FORMAT_UNSPECIFIED, service_provider, idp) == 'test method result'

    def test_identity_dict_creation(self):

        def random_method(self):
            return "test method result"

        User.random_method = random_method
        user = User()
        user.name = 'Test Name'
        user.email = 'test@email.com'
        user.other_setting = 'Test Setting'
        user.setting_not_passed = 'Test Setting Not Passed'

        service_provider = ServiceProvider(entity_id='entity-id', _attribute_mapping=json.dumps({
                'name': 'fullName',
                'email': 'emailAddress',
                'other_setting': 'otherSetting',
                'random_method': 'randomMethodTest'
            }))
        _ = IDP.load().config

        expected_result = {
            'fullName': 'Test Name',
            'emailAddress': 'test@email.com',
            'otherSetting': 'Test Setting',
            'randomMethodTest': 'test method result'
        }

        assert BaseProcessor('entity_id').create_identity(user, service_provider.attribute_mapping) == expected_result
