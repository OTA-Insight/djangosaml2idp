from django.urls import path

from . import views

app_name = 'djangosaml2idp'

urlpatterns = [
    path('sso/post', views.sso_entry, name="saml_login_post"),
    path('sso/redirect', views.sso_entry, name="saml_login_redirect"),
    path('sso/init', views.SSOInitView.as_view(), name="saml_idp_init"),
    path('login/process/', views.LoginProcessView.as_view(), name='saml_login_process'),
    path('login/process_multi_factor/', views.ProcessMultiFactorView.as_view(), name='saml_multi_factor'),
    path('metadata/', views.metadata, name='saml2_idp_metadata'),
]
