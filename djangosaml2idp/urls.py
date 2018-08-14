from django.conf.urls import url

from . import views

app_name = 'djangosaml2idp'

urlpatterns = [
    url(r'sso/post', views.sso_entry, name="saml_login_post"),
    url(r'sso/redirect', views.sso_entry, name="saml_login_redirect"),
    url(r'sso/init', views.SSOInitView.as_view(), name="saml_idp_init"),
    url(r'login/process/', views.LoginProcessView.as_view(), name='saml_login_process'),
    url(r'login/process_multi_factor/', views.ProcessMultiFactorView.as_view(), name='saml_multi_factor'),
    url(r'metadata/', views.metadata, name='saml2_idp_metadata'),
]