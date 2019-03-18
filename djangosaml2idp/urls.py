from django.urls import path

from . import views

app_name = 'djangosaml2idp'

urlpatterns = [
    path('sso/post', views.sso_entry, name="saml_login_post"),
    path('sso/redirect', views.sso_entry, name="saml_login_redirect"),
    # path('sso/init', views.SSOInitView.as_view(), name="saml_idp_init"),
    path('login/process/', views.LoginProcessView.as_view(), name='saml_login_process'),
    path('login/process_multi_factor/', views.ProcessMultiFactorView.as_view(), name='saml_multi_factor'),

    path('slo/redirect', views.slo_entry, name='saml_login_redirect'),
    path('slo/post', views.slo_entry, name='saml_login_post'),
    # path('slo/init', views.SLOInitView.as_view(), name="saml_slo_init"),
    path('slo/process', views.SLOInitView.as_view(), name="saml_logout_process"),

    path('metadata/', views.metadata, name='saml2_idp_metadata'),
]
