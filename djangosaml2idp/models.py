from datetime import timedelta

from django.db import models
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.utils import timezone
from django.utils.translation import gettext as _


class AgreementRecord(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL,
                             on_delete=models.CASCADE)
    sp_entity_id = models.CharField(max_length=512)
    attrs = models.TextField()
    created = models.DateTimeField(auto_now_add=True)
    modified = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ("user", "sp_entity_id")
        verbose_name = _('Agreement Record')
        verbose_name_plural = _('Agreement Records')

    def __str__(self):
        return '{}, {}'.format(self.user, self.modified)

    def is_expired(self):
        sp_config_dict = getattr(settings, 'SAML_IDP_SPCONFIG')
        if sp_config_dict is None:
            raise ImproperlyConfigured("Settings must define SP Configs.")

        sp_config = sp_config_dict.get(self.sp_entity_id)
        if sp_config is None:
            raise ImproperlyConfigured(_("No settings defined for this SP."))

        valid_for = sp_config.get("user_agreement_valid_for",
                                  getattr(settings,
                                          "SAML_IDP_USER_AGREEMENT_VALID_FOR"))
        if not valid_for:
            return False
        else:
            return timezone.now() > self.modified + timedelta(hours=valid_for)

    def wants_more_attrs(self, newAttrs):
        return bool(set(newAttrs).difference(self.attrs.split(",")))
