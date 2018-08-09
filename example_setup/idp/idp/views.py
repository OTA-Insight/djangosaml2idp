from django.conf import settings
from django.views.generic import TemplateView


class IndexView(TemplateView):
    template_name = "idp/index.html"

    def get_context_data(self, **kwargs):
        context = super(IndexView, self).get_context_data(**kwargs)
        context.update({
            "logout_url": settings.LOGOUT_URL,
            "login_url": settings.LOGIN_URL,
        })
        if self.request.user.is_authenticated:
            context.update({
                "user_attrs": sorted([(field.name, getattr(self.request.user, field.name)) for field in self.request.user._meta.get_fields() if field.concrete]),
                "known_sp_ids": [x for x in settings.SAML_IDP_SPCONFIG],
            })
        return context
