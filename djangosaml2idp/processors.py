import hashlib

from django.conf import settings
from saml2.saml import (NAMEID_FORMAT_UNSPECIFIED,
                        NAMEID_FORMAT_TRANSIENT,
                        NAMEID_FORMAT_PERSISTENT,
                        NAMEID_FORMAT_EMAILADDRESS,
                        NAMEID_FORMAT_X509SUBJECTNAME,
                        NAMEID_FORMAT_WINDOWSDOMAINQUALIFIEDNAME,
                        NAMEID_FORMAT_KERBEROS,
                        NAMEID_FORMAT_ENTITY,
                        NAMEID_FORMAT_ENCRYPTED)


class NameIdBuilder:
    """ Processor with methods to retrieve nameID standard format
        see: https://wiki.shibboleth.net/confluence/display/CONCEPT/NameIdentifiers
    """

    format_mappings = {
        NAMEID_FORMAT_UNSPECIFIED: 'get_nameid_unspecified',
        NAMEID_FORMAT_TRANSIENT: 'get_nameid_transient',
        NAMEID_FORMAT_PERSISTENT: 'get_nameid_persistent',
        NAMEID_FORMAT_EMAILADDRESS: 'get_nameid_email',
        # TODO: need to be implemented
        NAMEID_FORMAT_X509SUBJECTNAME: None,
        NAMEID_FORMAT_WINDOWSDOMAINQUALIFIEDNAME: None,
        NAMEID_FORMAT_KERBEROS: None,
        NAMEID_FORMAT_ENTITY: None,
        NAMEID_FORMAT_ENCRYPTED: None
    }

    @classmethod
    def _get_nameid_opaque(cls, user_id, salt=b''):
        """ Returns opaque salted unique identifiers
        """
        salted_value = user_id.encode()+salt
        opaque = hashlib.sha256(salted_value)
        return opaque.hexdigest()

    @classmethod
    def get_nameid_persistent(cls, user_id, sp_entityid='', idp_entityid='', user=None):
        """ Get PersistentID in TransientID format
            see: http://software.internet2.edu/eduperson/internet2-mace-dir-eduperson-201602.html#eduPersonTargetedID
        """
        return '!'.join([idp_entityid, sp_entityid, cls._get_nameid_opaque(user_id, salt=str(user.pk).encode())])

    @classmethod
    def get_nameid_email(cls, user_id, **kwargs):
        if '@' not in user_id:
            raise Exception("user_id {} does not contain the '@' symbol, so is not a valid NameID Email address format.".format(user_id))
        return user_id

    @classmethod
    def get_nameid_transient(cls, user_id, **kwargs):
        """ This would return EPPN
        """
        return user_id

    @classmethod
    def get_nameid_unspecified(cls, user_id, **kwargs):
        """ returns user_id as is
        """
        return user_id

    @classmethod
    def get_nameid(cls, user_id, nameid_format, **kwargs):
        method = cls.format_mappings.get(nameid_format)
        if not method:
            raise NotImplementedError('{} was not been mapped in NameIdBuilder.format_mappings'.format(nameid_format))
        if not hasattr(cls, method):
            raise NotImplementedError('{} was not been implemented NameIdBuilder methods'.format(nameid_format))
        name_id = getattr(cls, method)(user_id, **kwargs)
        return name_id


class BaseProcessor:
    """ Processor class is used to:
        - determine if a user has access to a client service of this IDP
        - construct the identity dictionary which is sent to the SP
        Subclass this to provide your own desired behaviour.
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

    def get_user_id(self, user, sp, idp_config):
        """ Get identifier for a user. Take the one defined in
            settings.SAML_IDP_DJANGO_USERNAME_FIELD first, if not set
            use the USERNAME_FIELD property which is set on the
            user Model. This defaults to the user.username field.
        """
        user_field_str = sp['config'].get('nameid_field') or getattr(settings, 'SAML_IDP_DJANGO_USERNAME_FIELD', None) or getattr(user, 'USERNAME_FIELD', 'username')
        user_field = getattr(user, user_field_str)

        if callable(user_field):
            user_id = str(user_field())
        else:
            user_id = str(user_field)

        # returns in a real name_id format
        return NameIdBuilder.get_nameid(user_id, sp['name_id_format'], sp_entityid=sp['id'], idp_entityid=idp_config.entityid, user=user)

    def create_identity(self, user, sp_attribute_mapping: dict = None):
        """ Generate an identity dictionary of the user based on the
            given mapping of desired user attributes by the SP
        """
        if sp_attribute_mapping is None:
            attribute_mapping = {'username': 'username'}
        else:
            attribute_mapping = sp_attribute_mapping
        # sp_mapping = sp['config'].get('attribute_mapping')

        results = {}
        for user_attr, out_attr in attribute_mapping.items():
            if hasattr(user, user_attr):
                attr = getattr(user, user_attr)
                results[out_attr] = attr() if callable(attr) else attr
        return results
