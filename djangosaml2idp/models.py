from datetime import timedelta

from django.db import models
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.utils import timezone


class AgreementRecord(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    sp_entity_id = models.TextField()
    attrs = models.TextField()
    date = models.DateTimeField(default=timezone.now)

    class Meta:
        unique_together = ("user", "sp_entity_id")

    def is_expired(self):
        sp_config_dict = getattr(settings, 'SAML_IDP_SPCONFIG')
        if sp_config_dict is None:
            raise ImproperlyConfigured("Settings must define SP Configs.")

        sp_config = sp_config_dict.get(self.sp_entity_id)
        if sp_config is None:
            raise ImproperlyConfigured("No settings defined for this SP.")

        valid_for = sp_config.get("user_agreement_valid_for", getattr(settings, "SAML_IDP_USER_AGREEMENT_VALID_FOR"))
        if not valid_for:
            return False
        else:
            return timezone.now() > self.date + timedelta(hours=valid_for)

    def wants_more_attrs(self, newAttrs):
        return bool(set(newAttrs).difference(self.attrs.split(",")))
