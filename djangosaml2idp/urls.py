from __future__ import absolute_import, division, print_function, unicode_literals

from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^sso/post', views.sso_entry, name="saml_login_post"),
    url(r'^sso/redirect', views.sso_entry, name="saml_login_redirect"),
    url(r'^login/process/$', views.login_process, name='saml_login_process'),
    url(r'^metadata/$', views.metadata, name='saml2_idp_metadata'),
]
