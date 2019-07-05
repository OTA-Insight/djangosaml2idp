from __future__ import (absolute_import, division, print_function,
                        unicode_literals)

from django.conf.urls import url

from . import views

app_name = 'djangosaml2idp'

urlpatterns = [
    # url(r'^login/$', views.LoginAuthView.as_view(), name='login'),
    # url(r'^sso/init', views.SSOInitView.as_view(), name="saml_idp_init"),
    url(r'^sso/(?P<binding>[a-zA-Z]+)/$', views.sso_entry, name="saml_login_binding"),
    url(r'^login/process/$', views.LoginProcessView.as_view(),
        name='saml_login_process'),
    # url(r'^login/process_multi_factor/$', views.get_metadata,
    #     name='saml_multi_factor'),
    # url(r'^login/process_user_agreement/$', views.UserAgreementScreen.as_view(),
    #     name='saml_user_agreement'),
    url(r'^slo/(?P<binding>[a-zA-Z]+)', views.LogoutProcessView.as_view(),
        name="saml_logout_binding"),
    url(r'^metadata/$', views.metadata, name='saml2_idp_metadata'),
]
