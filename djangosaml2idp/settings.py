from django.conf import settings


SERVICE_PROVIDER_MODEL = getattr(settings, 'SAML_IDP_SERVICE_PROVIDER_MODEL', 'djangosaml2idp.ServiceProvider')
PERSISTENT_ID_MODEL = getattr(settings, 'SAML_IDP_PERSISTENT_ID_MODEL', 'djangosaml2idp.PersistentId')
SERVICE_PROVIDER_ADMIN_CLASS = getattr(settings, 'SAML_IDP_SERVICE_PROVIDER_ADMIN_CLASS', 'djangosaml2idp.admin.ServiceProviderAdmin')
PERSISTENT_ID_ADMIN_CLASS = getattr(settings, 'SAML_IDP_PERSISTENT_ID_ADMIN_CLASS', 'djangosaml2idp.admin.PersistentIdAdmin')
