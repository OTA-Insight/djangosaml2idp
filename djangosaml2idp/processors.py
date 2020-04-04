import hashlib
import logging
from typing import Dict, Type

from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.utils.module_loading import import_string
from django.utils.translation import gettext as _
from saml2.saml import (NAMEID_FORMAT_EMAILADDRESS, NAMEID_FORMAT_ENCRYPTED,
                        NAMEID_FORMAT_ENTITY, NAMEID_FORMAT_KERBEROS,
                        NAMEID_FORMAT_PERSISTENT, NAMEID_FORMAT_TRANSIENT,
                        NAMEID_FORMAT_UNSPECIFIED,
                        NAMEID_FORMAT_WINDOWSDOMAINQUALIFIEDNAME,
                        NAMEID_FORMAT_X509SUBJECTNAME)

from .models import ServiceProvider

logger = logging.getLogger(__name__)

User = get_user_model()


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
    def _get_nameid_opaque(cls, user_id: str, salt: bytes = b'', *args, **kwargs) -> str:
        """ Returns opaque salted unique identifiers
        """
        salted_value = user_id.encode() + salt
        opaque = hashlib.sha256(salted_value)
        return opaque.hexdigest()

    @classmethod
    def get_nameid_persistent(cls, user_id: str, user: User, sp_entityid: str = '', idp_entityid: str = '') -> str:  # type: ignore
        """ Get PersistentID in TransientID format
            see: http://software.internet2.edu/eduperson/internet2-mace-dir-eduperson-201602.html#eduPersonTargetedID
        """
        return '!'.join([idp_entityid, sp_entityid, cls._get_nameid_opaque(user_id, salt=str(user.pk).encode())])  # type: ignore

    @classmethod
    def get_nameid_email(cls, user_id: str, **kwargs) -> str:
        if '@' not in user_id:
            raise Exception(f"user_id {user_id} does not contain the '@' symbol, so is not a valid NameID Email address format.")
        return user_id

    @classmethod
    def get_nameid_transient(cls, user_id: str, **kwargs) -> str:
        """ This would return EPPN
        """
        raise NotImplementedError('Not implemented yet')

    @classmethod
    def get_nameid_unspecified(cls, user_id: str, **kwargs) -> str:
        """ returns user_id as is
        """
        return user_id

    @classmethod
    def get_nameid(cls, user_id: str, nameid_format: str, **kwargs) -> str:
        method = cls.format_mappings.get(nameid_format)
        if not method:
            raise NotImplementedError(f'{nameid_format} has not been mapped in NameIdBuilder.format_mappings')
        if not hasattr(cls, method):
            raise NotImplementedError(f'{nameid_format} has not been implemented NameIdBuilder methods')
        name_id = getattr(cls, method)(user_id, **kwargs)
        return name_id


class BaseProcessor:
    """ Processor class is used to:
        - determine if a user has access to a client service of this IDP
        - construct the identity dictionary which is sent to the SP
        Subclass this to provide your own desired behaviour.
    """

    def __init__(self, entity_id: str):
        self._entity_id = entity_id

    def has_access(self, request) -> bool:
        """ Check if this user is allowed to use this IDP
        """
        return True

    def enable_multifactor(self, user) -> bool:
        """ Check if this user should use a second authentication system
        """
        return False

    def get_user_id(self, user, name_id_format: str, service_provider: ServiceProvider, idp_config) -> str:
        """ Get identifier for a user.
        """
        user_field_str = service_provider.nameid_field
        user_field = getattr(user, user_field_str)

        if callable(user_field):
            user_id = str(user_field())
        else:
            user_id = str(user_field)

        # returns in a real name_id format
        return NameIdBuilder.get_nameid(user_id, name_id_format, sp_entityid=service_provider.entity_id, idp_entityid=idp_config.entityid, user=user)

    def create_identity(self, user, sp_attribute_mapping: Dict[str, str]) -> Dict[str, str]:
        """ Generate an identity dictionary of the user based on the
            given mapping of desired user attributes by the SP
        """
        results = {}
        for user_attr, out_attr in sp_attribute_mapping.items():
            if hasattr(user, user_attr):
                attr = getattr(user, user_attr)
                results[out_attr] = attr() if callable(attr) else attr
        return results


def validate_processor_path(processor_class_path: str) -> Type[BaseProcessor]:
    try:
        processor_cls = import_string(processor_class_path)
    except ImportError as e:
        msg = _("Failed to import processor class {}").format(processor_class_path)
        logger.error(msg, exc_info=True)
        raise ValidationError(msg) from e
    return processor_cls


def instantiate_processor(processor_cls: Type[BaseProcessor], entity_id: str) -> Type[BaseProcessor]:
    try:
        processor_instance = processor_cls(entity_id)  # type: ignore
    except Exception as e:
        msg = _("Failed to instantiate processor: {} - {}").format(processor_cls, e)
        logger.error(msg, exc_info=True)
        raise ImproperlyConfigured(msg) from e
    if not isinstance(processor_instance, BaseProcessor):
        raise ValidationError('{} should be a subclass of djangosaml2idp.processors.BaseProcessor'.format(processor_cls))
    return processor_instance  # type: ignore
