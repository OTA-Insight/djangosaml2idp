from django.contrib.auth import views as auth_views
from django.urls import include, path
from django.views.generic import View

from djangosaml2.views import login as djangosaml2_login

from . import views

app_name = 'example_sp'


class SSOLoginView(View):
    def get(self, request, *args, **kwargs):
        return djangosaml2_login(request, post_binding_form_template='djangosaml2/example_post_binding_form.html')
        # The one below is the same template but without the |safe filters. Try using this one. 
        # return djangosaml2_login(request, post_binding_form_template='sp/non_safe_post_binding_form.html')


urlpatterns = [
    path('logout/', auth_views.LogoutView.as_view()),
    path('saml2/login/', SSOLoginView.as_view()),
    path('saml2/', include('djangosaml2.urls')),
    path('', views.IndexView.as_view()),
]
