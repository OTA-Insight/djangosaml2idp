from __future__ import absolute_import, division, print_function, unicode_literals

from django.conf.urls import url

from . import views

app_name = 'djangosaml2idp'

urlpatterns = [
    url('^login/', views.LoginAuthView.as_view(), name='login'),
    url('^sso/init', views.SSOInitView.as_view(), name="saml_idp_init"),
    url('^sso/<str:binding>', views.sso_entry, name="saml_login_binding"),
    url('^login/process/$', views.LoginProcessView.as_view(),
         name='saml_login_process'),
    url('^login/process_multi_factor/$', views.get_metadata,
         name='saml_multi_factor'),
    url('^login/process_user_agreement/',
         views.UserAgreementScreen.as_view(), name='saml_user_agreement'),
    url('^slo/<str:binding>', views.LogoutProcessView.as_view(),
         name="saml_logout_binding"),
    url('^metadata/$', views.metadata, name='saml2_idp_metadata'),
]
