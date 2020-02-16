import json

import pytest
from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.http import HttpRequest
from saml2.saml import NAMEID_FORMAT_UNSPECIFIED

from djangosaml2idp.idp import IDP
from djangosaml2idp.models import ServiceProvider
from djangosaml2idp.processors import (BaseProcessor, NameIdBuilder,
                                       instantiate_processor,
                                       validate_processor_path)

User = get_user_model()


class TestBaseProcessor:

    def test_validate_processor_path_builtin_baseprocessor_valid(self):
        proc_cls = validate_processor_path('djangosaml2idp.processors.BaseProcessor')
        assert isinstance(proc_cls(''), BaseProcessor)

    def test_validate_processor_path_nonexisting(self):
        with pytest.raises(ValidationError, match='Failed to import processor class'):
            validate_processor_path('dummy.processors.does_not_exist')

    def test_instantiate_processor_failing_cls(self):
        class FailingProcessor:
            def __init__(self, *args, **kwargs):
                raise NotImplementedError

        with pytest.raises(ImproperlyConfigured, match='Failed to instantiate processor: '):
            instantiate_processor(FailingProcessor, '')

    def test_instantiate_processor_wrong_cls(self):
        class RandomObject:
            def __init__(self, *args, **kwargs):
                pass

        with pytest.raises(ValidationError, match='should be a subclass of djangosaml2idp.processors.BaseProcessor'):
            instantiate_processor(RandomObject, '')

    def test_instantiate_processor_valid(self):
        proc = instantiate_processor(BaseProcessor, 'entity_id')
        assert isinstance(proc, BaseProcessor)

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

    @pytest.mark.django_db
    def test_extract_user_id_configure_by_settings(self, settings):
        """Should use `settings.SAML_IDP_DJANGO_USERNAME_FIELD` to determine the user id field"""

        settings.SAML_IDP_DJANGO_USERNAME_FIELD = 'first_name'

        user = User(first_name='test_first_name')
        service_provider = ServiceProvider(entity_id='entity-id')
        idp = IDP.load().config

        assert BaseProcessor('entity-id').get_user_id(user, NAMEID_FORMAT_UNSPECIFIED, service_provider, idp) == 'test_first_name'

    @pytest.mark.django_db
    def test_extract_user_id_configure_on_service_provider(self):
        user = User()
        user.USERNAME_FIELD = 'email'
        user.email = 'test_email'

        service_provider = ServiceProvider(entity_id='entity-id', _nameid_field='email')
        idp = IDP.load().config

        assert BaseProcessor('entity-id').get_user_id(user, NAMEID_FORMAT_UNSPECIFIED, service_provider, idp) == 'test_email'

    @pytest.mark.django_db
    def test_extract_user_id_from_sp_config_if_method(self):

        def random_method(self):
            return "test method result"

        User.random_method = random_method

        user = User()

        service_provider = ServiceProvider(entity_id='entity-id', _nameid_field='random_method')
        idp = IDP.load().config

        assert BaseProcessor('entity-id').get_user_id(user, NAMEID_FORMAT_UNSPECIFIED, service_provider, idp) == 'test method result'

    @pytest.mark.django_db
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


class TestNameIdBuilder:
    def test_get_nameid_opaque(self):
        user = User(username='Test Name', email='test@email.com')

        assert NameIdBuilder._get_nameid_opaque(user.username) == 'b19cfa3a0f7cef07dc1dd1604cee0a49c57d0e1a4f1baa864ba1c7c2229b147f'

    def test_get_nameid_persistent(self):
        user = User(username='Test Name', email='test@email.com')

        fully_qualified = NameIdBuilder.get_nameid_persistent(user.username, user=user, sp_entityid='sp_entity_id', idp_entityid='idp_entity_id')
        assert fully_qualified == 'idp_entity_id!sp_entity_id!86bb5037f0bf1a9cc7918296437fd560915c182316f23a3f4db480018eb1c71f'

        no_sp_idp_ids = NameIdBuilder.get_nameid_persistent(user.username, user=user)
        assert no_sp_idp_ids == '!!86bb5037f0bf1a9cc7918296437fd560915c182316f23a3f4db480018eb1c71f'

    def test_get_nameid_unspecified(self):
        user = User(username='Test Name', email='test@email.com')

        assert NameIdBuilder.get_nameid_unspecified(user.username) == user.username

    def test_get_nameid_transient(self):
        user = User(username='Test Name', email='test@email.com')

        with pytest.raises(NotImplementedError):
            NameIdBuilder.get_nameid_transient(user.username)

    def test_get_nameid_email_valid(self):
        user = User(username='Test Name', email='test@email.com')

        assert NameIdBuilder.get_nameid_email(user.email) == 'test@email.com'

    def test_get_nameid_email_invalid(self):
        user = User(username='Test Name', email='test@email.com')

        with pytest.raises(Exception, message=f"user_id {user.username} does not contain the '@' symbol, so is not a valid NameID Email address format."):
            NameIdBuilder.get_nameid_email(user.username)

    def test_request_unmapped_nameid(self):
        user = User(username='Test Name', email='test@email.com')
        requested_nameid_format = 'unmapped_nameid_format'

        with pytest.raises(NotImplementedError, match=f'{requested_nameid_format} has not been mapped in NameIdBuilder.format_mappings'):
            NameIdBuilder.get_nameid(user.username, nameid_format=requested_nameid_format)

    def test_request_unimplemented_nameid(self):
        user = User(username='Test Name', email='test@email.com')

        requested_nameid_format = 'notimplemented_nameid_format'
        NameIdBuilder.format_mappings[requested_nameid_format] = 'nonexisting_method'

        with pytest.raises(NotImplementedError, match=f'{requested_nameid_format} has not been implemented NameIdBuilder methods'):
            NameIdBuilder.get_nameid(user.username, nameid_format=requested_nameid_format)
