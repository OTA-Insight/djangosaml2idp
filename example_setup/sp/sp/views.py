from django.conf import settings
from django.contrib.auth.models import User
from django.dispatch import receiver
from django.views.generic import TemplateView
from djangosaml2.signals import pre_user_save


class IndexView(TemplateView):
    template_name = "sp/index.html"

    def get_context_data(self, **kwargs):
        context = super(IndexView, self).get_context_data(**kwargs)
        context.update({
            "logout_url": settings.LOGOUT_URL,
            "login_url": settings.LOGIN_URL,
        })
        if self.request.user.is_authenticated:
            context.update({
                "user_attrs": sorted([(field.name, getattr(self.request.user, field.name)) for field in self.request.user._meta.get_fields() if field.concrete]),
            })
        return context


# TODO fix this in IdP side?
@receiver(pre_user_save, sender=User)
def custom_update_user(sender, instance, attributes, user_modified, **kargs):
    """ Default behaviour does not play nice with booleans encoded in SAML as u'true'/u'false'.
        This will convert those attributes to real booleans when saving.
    """
    for k, v in attributes.items():
        u = set.intersection(set(v), set([u'true', u'false']))
        if u:
            setattr(instance, k, u.pop() == u'true')
    return True  # I modified the user object
