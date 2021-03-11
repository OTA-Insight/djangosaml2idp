Configuration & Usage
=====================

The first thing you need to do is add ``djangosaml2idp`` to the list of installed apps::

    INSTALLED_APPS = (
        'django.contrib.admin',
        'djangosaml2idp',
        ...
    )

Now include ``djangosaml2idp`` in your project by adding it in the url config::

    from django.conf.urls import url, include
    from django.contrib import admin

    urlpatterns = [
        url(r'^idp/', include('djangosaml2idp.urls')),
        url(r'^admin/', admin.site.urls),
        ...
    ]

Run the migrations for the app.

In your Django settings, configure your IdP. Configuration follows the `PySAML2 configuration <https://github.com/IdentityPython/pysaml2/blob/master/docs/howto/config.rst>`_. The IdP from the example project looks like this::

    import saml2
    from saml2.saml import NAMEID_FORMAT_EMAILADDRESS, NAMEID_FORMAT_UNSPECIFIED
    from saml2.sigver import get_xmlsec_binary

    LOGIN_URL = '/login/'
    BASE_URL = 'http://localhost:9000/idp'

    SAML_IDP_CONFIG = {
        'debug' : DEBUG,
        'xmlsec_binary': get_xmlsec_binary(['/opt/local/bin', '/usr/bin/xmlsec1']),
        'entityid': '%s/metadata' % BASE_URL,
        'description': 'Example IdP setup',

        'service': {
            'idp': {
                'name': 'Django localhost IdP',
                'endpoints': {
                    'single_sign_on_service': [
                        ('http://localhost:9000/idp/sso/post/', saml2.BINDING_HTTP_POST),
                        ('http://localhost:9000/idp/sso/redirect/', saml2.BINDING_HTTP_REDIRECT),
                    ],
                    "single_logout_service": [
                        ("http://localhost:9000/idp/slo/post/", saml2.BINDING_HTTP_POST),
                        ("http://localhost:9000/idp/slo/redirect/", saml2.BINDING_HTTP_REDIRECT)
                    ],
                },
                'name_id_format': [NAMEID_FORMAT_EMAILADDRESS, NAMEID_FORMAT_UNSPECIFIED],
                'sign_response': True,
                'sign_assertion': True,
                'want_authn_requests_signed': True,
            },
        },

        # Signing
        'key_file': BASE_DIR + '/certificates/private.key',
        'cert_file': BASE_DIR + '/certificates/public.cert',
        # Encryption
        'encryption_keypairs': [{
            'key_file': BASE_DIR + '/certificates/private.key',
            'cert_file': BASE_DIR + '/certificates/public.cert',
        }],
        'valid_for': 365 * 24,
    }


Notice the configuration requires a private key and public certificate to be available on the filesystem in order to sign and encrypt messages.

Dynamic IdP configuration
-------------------------

Aditionaly a callback can be used to customize the IdP settings on a per-request basis. It can be defined either
* as a path set in the `SAML_IDP_CONFIG_LOADER` 
* by subclassing the views (and using them in the url config) and overriding their `get_config_loader_path(self, request: HttpRequest)` method, returning a callback or a path to it

Any of these callbacks will be called when loading the IdP, receiving the static configuration (defined by `SAML_IDP_CONFIG`) and the current request as arguments. It is expected to return a new configuration with the same form as the static one.

Please note that the resulting IDP objects will be cached with the 'entityid' parameter as a key.

Service Providers
-----------------

Next the Service Providers and their configuration need to be added, this is done via the Django admin interface. Add an entry for each SP which speaks to thie IdP.
Add a copy of the local metadata xml, or set a remote metadata url. Add an attribute mapping for user attributes to SAML fields or leave the default mapping which will be prefilled.

Several attributes can be overriden per SP. If they aren't overridden explicitly, they will use the 'global' settings which can be configured for your Django installation.
If those aren't set, some defaults will be used, as indicated in the admin when you configre a SP.
The resulting configuration of a SP, with merged settings of its own and the instance settings and defaults, is shown in the admin as a summary.

The set of SPs available can optionnaly be dynamically defined through the `SAML_IDP_FILTER_SP_QUERYSET` setting, as a path to a callable. It receives the orginal queryset (all SPs with `active=True` field) and the current request as arguments. It is expected to return a queryset.

Further optional configuration options
======================================
 
In the ``SAML_IDP_SPCONFIG`` setting you can define a ``processor``, its value being a string with dotted path to a class.
This is a hook to customize some access control checks. By default, the included `BaseProcessor` is used, which allows every user to login on the IdP.
You can customize this behaviour by subclassing the `BaseProcessor` and overriding its `has_access(self, request)` method. This method should return true or false, depending if the user has permission to log in for the SP / IdP.
The processor has the SP entity ID available as `self._entity_id`, and received the request (with an authenticated request.user on it) as parameter to the `has_access` function.
This way, you should have the necessary flexibility to perform whatever checks you need.
An example `processor subclass <https://github.com/OTA-Insight/djangosaml2idp/blob/master/example_setup/idp/idp/processors.py>`_ can be found in the IdP of the included example.
Use this metadata xml to configure your SP. Place the metadata xml from that SP in the location specified in the config dict (sp_metadata.xml in the example above).

Without custom setting, users will be identified by the ``USERNAME_FIELD`` property on the user Model you use. By Django defaults this will be the username.
You can customize which field is used for the identifier by adding ``SAML_IDP_DJANGO_USERNAME_FIELD`` to your settings with as value the attribute to use on your user instance.

Other settings you can set as defaults to be used if not overriden by an SP are `SAML_AUTHN_SIGN_ALG`, `SAML_AUTHN_DIGEST_ALG`, and `SAML_ENCRYPT_AUTHN_RESPONSE`. They can be set if desired in the django settings, in which case they will be used for all ServiceProviders configuration on this instance if they don't override it. E.g.:

    SAML_AUTHN_SIGN_ALG = saml2.xmldsig.SIG_RSA_SHA256
    SAML_AUTHN_DIGEST_ALG = saml2.xmldsig.DIGEST_SHA256

In case your SP does not properly expose validuntil in metadata, you can provide fallback setting for it using::

    SAML_IDP_FALLBACK_EXPIRATION_DAYS = 30

The default value for the fields ``processor`` and ``attribute_mapping`` can be set via the settings (the values displayed here are the defaults)::

    SAML_IDP_SP_FIELD_DEFAULT_PROCESSOR = 'djangosaml2idp.processors.BaseProcessor'
    SAML_IDP_SP_FIELD_DEFAULT_ATTRIBUTE_MAPPING = {"email": "email", "first_name": "first_name", "last_name": "last_name", "is_staff": "is_staff", "is_superuser": "is_superuser"}
