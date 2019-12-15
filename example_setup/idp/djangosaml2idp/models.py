import json
import logging
from typing import Dict, Union

import saml2.xmldsig
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.db import models
from django.utils.module_loading import import_string
from django.utils.translation import gettext as _

from .processors import BaseProcessor

logger = logging.getLogger(__name__)


def validate_processor_path(processor_class_path):
    try:
        processor_cls = import_string(processor_class_path)
    except ImportError as e:
        msg = _("Failed to import processor class {}").format(processor_class_path)
        logger.error(msg, exc_info=True)
        raise ValidationError(msg) from e
    return processor_cls


def instantiate_processor(processor_cls, entity_id: str):
    try:
        processor_instance = processor_cls(entity_id)
    except Exception as e:
        msg = _("Failed to instantiate processor: {} - {}").format(processor_cls, e)
        logger.error(msg, exc_info=True)
        raise
    if not isinstance(processor_instance, BaseProcessor):
        raise ValidationError('{} should be a subclass of djangosaml2idp.processors.BaseProcessor'.format(processor_cls))
    return processor_instance


# TODO: factory for / and testing

class ServiceProvider(models.Model):
    # Bookkeeping
    dt_created = models.DateTimeField(verbose_name='Created at', auto_now_add=True)
    dt_updated = models.DateTimeField(verbose_name='Updated at', auto_now=True, null=True, blank=True)

    # Identification
    entity_id = models.CharField(verbose_name='Entity ID', max_length=256, unique=True)
    pretty_name = models.CharField(verbose_name='Pretty Name', blank=True, max_length=256, help_text='For display purposes, can be empty')
    description = models.TextField(verbose_name='Description', blank=True)
    metadata = models.TextField(verbose_name='Metadata XML', blank=True, help_text='XML containing the metadata')

    # Configuration
    active = models.BooleanField(verbose_name='Active', default=True)
    _processor = models.CharField(verbose_name='Processor', max_length=256, help_text='Import string for the (access) Processor to use.', default='djangosaml2idp.processors.BaseProcessor')
    _attribute_mapping = models.TextField(verbose_name='Attribute mapping', default='{}', help_text='dict with the mapping from django attributes to saml attributes in the identity')

    _nameid_field = models.CharField(verbose_name='NameID Field', blank=True, max_length=64, help_text='Attribute on the user to use as identifier during the NameID construction. Can be a callable. If not set, this will default to settings.SAML_IDP_DJANGO_USERNAME_FIELD; if that is not set, it will use the `USERNAME_FIELD` attribute on the active user model.')

    # TODO: allow null, in which case it should default to global setting
    # TODO: access property with fallback to default
    _sign_response = models.BooleanField(verbose_name='Sign response', null=True)
    _sign_assertion = models.BooleanField(verbose_name='Sign assertion', null=True)

    signing_algorithm = models.CharField(verbose_name='Signing algorithm', choices=[(constant, pretty) for (pretty, constant) in saml2.xmldsig.SIG_ALLOWED_ALG], default=settings.SAML_AUTHN_SIGN_ALG, max_length=256)
    digest_algorithm = models.CharField(verbose_name='Digest algorithm', choices=[(constant, pretty) for (pretty, constant) in saml2.xmldsig.DIGEST_ALLOWED_ALG], default=settings.SAML_AUTHN_DIGEST_ALG, max_length=256)

    # TODO: help_text, what does this do exactly?
    # TODO: access property with fallback to default
    _encrypt_saml_responses = models.BooleanField(verbose_name='Encrypt SAML Response', default=False, null=True)

    class Meta:
        verbose_name = "Service Provider"
        verbose_name_plural = "Service Providers"
        indexes = [
            models.Index(fields=['entity_id', ]),
        ]

    def __str__(self):
        if self.pretty_name:
            return f'{self.pretty_name} ({self.entity_id})'
        return f'{self.entity_id}'

    @property
    def attribute_mapping(self) -> Dict[str, str]:
        if not self._attribute_mapping:
            return {'username': 'username'}
        return json.loads(self._attribute_mapping)

    @attribute_mapping.setter
    def attribute_mapping(self, value: Union[str, Dict[str, str]]):
        # Do some cleaning and validation
        if isinstance(value, str):
            value = json.loads(value)
        if not isinstance(value, dict):
            raise ValidationError('The provided attribute_mapping should be either a dict or a string representing a dict.')
        for k, v in value.items():
            if not isinstance(k, str) or not isinstance(v, str):
                raise ValidationError('The provided attribute_mapping should be a dict with strings for both all keys and values.')
        self._attribute_mapping = json.dumps(value, indent=4)

    @property
    def nameid_field(self):
        if self._nameid_field:
            return self._nameid_field
        if hasattr(settings, 'SAML_IDP_DJANGO_USERNAME_FIELD'):
            return settings.SAML_IDP_DJANGO_USERNAME_FIELD
        return getattr(settings.AUTH_USER_MODEL, 'USERNAME_FIELD', 'username')

    # Do checks on validity of processor string both on setting and getting, as the
    # codebase can change regardless of the objects persisted in the database.

    @property
    def processor(self):
        processor_cls = validate_processor_path(self._processor)
        return instantiate_processor(processor_cls, self.entity_id)

    @processor.setter
    def processor(self, value: str):
        processor_cls = validate_processor_path(value)
        instantiate_processor(processor_cls, self.entity_id)

    @property
    def sign_response(self):
        if self._sign_response is None:
            idp = get_idp_config()
            return idp.config.getattr("sign_response", False)
        return self._sign_response

    @property
    def sign_assertion(self):
        if self._sign_assertion is None:
            idp = get_idp_config()
            return idp.config.getattr("sign_assertion", False)
        return self._sign_assertion

    @property
    def encrypt_saml_responses(self):
        if self._encrypt_saml_responses is None:
            return getattr(settings, "SAML_AUTHN_SIGN_ALG", xmldsig.SIG_RSA_SHA256)
        return self._encrypt_saml_responses
