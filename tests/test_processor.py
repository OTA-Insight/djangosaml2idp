from django.contrib.auth import get_user_model
from djangosaml2idp.processors import BaseProcessor

User = get_user_model()


class TestBaseProcessor:

    def test_extract_user_id_configure_by_user_class(self):

        user = User()
        user.USERNAME_FIELD = 'email'
        user.email = 'test_email'

        assert BaseProcessor('entity-id').get_user_id(user) == 'test_email'

    def test_extract_user_id_configure_by_settings(self, settings):
        """Should use `settings.SAML_IDP_DJANGO_USERNAME_FIELD` to determine the user id field"""

        settings.SAML_IDP_DJANGO_USERNAME_FIELD = 'first_name'

        user = User()
        user.first_name = 'test_first_name'

        assert BaseProcessor('entity-id').get_user_id(user) == 'test_first_name'

    def test_extract_user_id_from_sp_config(self):

        user = User()
        user.special_id = 'test_special_id'

        sp_config = {
            'nameid_field': 'special_id'
        }

        assert BaseProcessor('entity_id').get_user_id(user, sp_config) == 'test_special_id'

    def test_identity_dict_creation(self):

        user = User()
        user.name = 'Test Name'
        user.email = 'test@email.com'
        user.other_setting = 'Test Setting'
        user.setting_not_passed = 'Test Setting Not Passed'

        sp_config = {
            'attribute_mapping': {
                'name': 'fullName',
                'email': 'emailAddress',
                'other_setting': 'otherSetting'
            }
        }

        expected_result = {
            'fullName': 'Test Name',
            'emailAddress': 'test@email.com',
            'otherSetting': 'Test Setting'
        }

        assert BaseProcessor('entity_id').create_identity(user, sp_config) == expected_result
