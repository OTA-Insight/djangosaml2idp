djangosaml2idp
===============


.. image:: https://img.shields.io/pypi/v/djangosaml2idp.svg
    :target: https://pypi.python.org/pypi/djangosaml2idp
    :alt: PyPi

.. image:: https://readthedocs.org/projects/djangosaml2idp/badge/?version=latest
    :alt: Documentation Status
    :scale: 100%
    :target: https://djangosaml2idp.readthedocs.io/en/latest/?badge=latest


djangosaml2idp implements the Identity Provider side of the SAML2 protocol for Django.
It builds on top of `PySAML2 <https://github.com/IdentityPython/pysaml2>`_, is the latest version compatible with Python 3 and Django 2.0+.
(version 0.3.3 of the package is to be used with Python2 and Django 1.11)

Any contributions, feature requests, proposals, ideas ... are welcome!

Installation
------------

PySAML2 uses `XML Security Library <http://www.aleksey.com/xmlsec/>`_ binary to sign SAML assertions, so you need to install
it either through your operating system package or by compiling the source code. It doesn't matter where the final executable is installed because
you will need to set the full path to it in the configuration stage. XmlSec is available (at least) for Debian, OSX and Alpine Linux.

Now you can install the djangosaml2idp package using pip. This will also install PySAML2 and its dependencies automatically::

    pip install djangosaml2idp


Configuration & Usage
---------------------
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

In your Django settings, configure your IdP. Configuration follows the `PySAML2 configuration <https://github.com/IdentityPython/pysaml2/blob/master/docs/howto/config.rst>`_. The IdP from the example project looks like this::

    ...
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
                        ('%s/sso/post' % BASE_URL, saml2.BINDING_HTTP_POST),
                        ('%s/sso/redirect' % BASE_URL, saml2.BINDING_HTTP_REDIRECT),
                    ],
                },
                'name_id_format': [NAMEID_FORMAT_EMAILADDRESS, NAMEID_FORMAT_UNSPECIFIED],
                'sign_response': True,
                'sign_assertion': True,
            },
        },

        'metadata': {
            'local': [os.path.join(os.path.join(os.path.join(BASE_DIR, 'idp'), 'saml2_config'), 'sp_metadata.xml')],
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

You also have to define a mapping for each SP you talk to:

    SAML_IDP_SPCONFIG = {
        'http://localhost:8000/saml2/metadata/': {
            'processor': 'djangosaml2idp.processors.BaseProcessor',
            'attribute_mapping': {
                # DJANGO: SAML
                'email': 'email',
                'first_name': 'first_name',
                'last_name': 'last_name',
                'is_staff': 'is_staff',
                'is_superuser':  'is_superuser',
            }
        }
    }

That's all for the IdP configuration. Assuming you run the Django development server on localhost:8000, you can get its metadata by visiting http://localhost:8000/idp/metadata/.
Use this metadata xml to configure your SP. Place the metadata xml from that SP in the location specified in the config dict (sp_metadata.xml in the example above).

Using the multi factor authentication support
---------------------------------------------------

There are three main components to adding multiple factor support.


1. Subclass djangosaml2idp.processors.BaseProcessor as outlined above. You will
need to override the `enable_multifactor()` method to check whether or not 
multifactor should be enabled for a user. (If it should allways be
enabled for all users simply hard code to True). By default it unconditionally
returns False and no multifactor is enforce.


2. Sublass the `djangosaml2idp.views.ProcessMultiFactorView` view to make the appropriate calls for your environment.
Implement your custom verification logic in the `multifactor_is_valid` method: this could call a helper script, an
internal SMS triggering service, a data source only the IdP can access or an external second factor provider like Symantec VIP ...
By default this view will log that it was called then redirect.


3. Update your urls.py and add an override for name='saml_multi_factor' - ensure it comes before importing the djangosaml2idp urls file so your custom view is used instead of the built-in one.


Example project
---------------
``example_project`` contains a barebone demo setup to demonstrate the login-logout functionality.
It consists of a Service Provider implemented with `djangosaml2 <https://github.com/knaperek/djangosaml2/>`_ and an Identity Provider using ``djangosaml2idp``.
