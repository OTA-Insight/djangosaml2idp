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
