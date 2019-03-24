from django.conf import settings


class BaseProcessor:
    """ Processor class is used to determine if a user has access to a
        client service of this IDP
        and to construct the identity dictionary which is sent to the SP
    """

    def __init__(self, entity_id):
        self._entity_id = entity_id

    def has_access(self, request):
        """ Check if this user is allowed to use this IDP
        """
        return True

    def enable_multifactor(self, user):
        """ Check if this user should use a second authentication system
        """
        return False

    def get_user_id(self, user, sp_config={}):
        """ Get identifier for a user. Take the one defined in
            settings.SAML_IDP_DJANGO_USERNAME_FIELD first, if not set
            use the USERNAME_FIELD property which is set on the
            user Model. This defaults to the user.username field.
        """
        user_field_str = sp_config.get('nameid_field') or \
            getattr(settings, 'SAML_IDP_DJANGO_USERNAME_FIELD', None) or \
            getattr(user, 'USERNAME_FIELD', 'username')
        user_field = getattr(user, user_field_str)
        if callable(user_field):
            return str(user_field())
        else:
            return str(user_field)

    def create_identity(self, user, sp_config):
        """ Generate an identity dictionary of the user based on the
            given mapping of desired user attributes by the SP
        """
        default_mapping = {'username': 'username'}
        sp_mapping = sp_config.get('attribute_mapping', default_mapping)

        results = {}
        for user_attr, out_attr in sp_mapping.items():
            if hasattr(user, user_attr):
                attr = getattr(user, user_attr)
                results[out_attr] = attr() if callable(attr) else attr
        return results
