djangosaml2idp
===============


.. image:: https://img.shields.io/pypi/v/djangosaml2idp.svg
    :scale: 100%
    :target: https://pypi.python.org/pypi/djangosaml2idp
    :alt: PyPi

.. image:: https://img.shields.io/pypi/pyversions/djangosaml2idp
    :scale: 100%
    :target: https://www.python.org/
    :alt: PyPI - Python Version

.. image:: https://img.shields.io/pypi/djversions/djangosaml2idp
    :scale: 100%
    :target: https://www.djangoproject.com/
    :alt: PyPI - Django Version

.. image:: https://readthedocs.org/projects/djangosaml2idp/badge/?version=latest
    :scale: 100%
    :target: https://djangosaml2idp.readthedocs.io/en/latest/?badge=latest
    :alt: Documentation Status

.. image:: https://img.shields.io/badge/License-Apache%202.0-blue.svg
    :scale: 100%
    :target: https://www.apache.org/licenses/LICENSE-2.0
    :alt: Apache 2.0 License

.. image:: https://codecov.io/gh/ota-insight/djangosaml2idp/branch/master/graph/badge.svg
    :scale: 100%
    :target: https://codecov.io/gh/ota-insight/djangosaml2idp
    :alt: Code coverage


djangosaml2idp implements the Identity Provider side of the SAML2 protocol for Django.
It builds on top of `PySAML2 <https://github.com/IdentityPython/pysaml2>`_, and is production-ready.

Any contributions, feature requests, proposals, ideas ... are welcome! See the `CONTRIBUTING document <https://github.com/OTA-Insight/djangosaml2idp/blob/master/CONTRIBUTING.md>`_ for some info.

Installation
============

PySAML2 uses `XML Security Library <http://www.aleksey.com/xmlsec/>`_ binary to sign SAML assertions, so you need to install
it either through your operating system package or by compiling the source code. It doesn't matter where the final executable is installed because
you will need to set the full path to it in the configuration stage. XmlSec is available (at least) for Debian, OSX and Alpine Linux.

Now you can install the djangosaml2idp package using pip. This will also install PySAML2 and its dependencies automatically::

    pip install djangosaml2idp


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

Next the Service Providers and their configuration need to be added, this is done via the Django admin interface. Add an entry for each SP which speaks to thie IdP.
Add a copy of the local metadata xml, or set a remote metadata url. Add an attribute mapping for user attributes to SAML fields or leave the default mapping which will be prefilled.

Several attributes can be overriden per SP. If they aren't overridden explicitly, they will use the 'global' settings which can be configured for your Django installation.
If those aren't set, some defaults will be used, as indicated in the admin when you configre a SP.
The resulting configuration of a SP, with merged settings of its own and the instance settings and defaults, is shown in the admin as a summary.

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

Customizing error handling
==========================

djangosaml2idp renders a very basic error page if it encounters an error, indicating an error occured, which error, and possibly an extra message.
The HTTP status code is dependant on which error occured. It also logs the exception with error severity.
You can customize this by using the ``SAML_IDP_ERROR_VIEW_CLASS`` setting. Set this to a dotted import path to your custom (class based) view in order to use that one.
You'll likely want this to use your own template and styling to display and error message.
If you subclass the provided `djangosaml2idp.error_views.SamlIDPErrorView`, you have the following variables available for use in the template:

exception
  the exception instance that occurred

exception_type
  the class of the exception that occurred

exception_msg
  the message from the exception (by doing `str(exception)`)

extra_message
  if no specific exception given, a message indicating something went wrong, or an additional message next to the `exception_msg`

The simplest override is to subclass the `SamlIDPErrorView` and only using your own error template.
You can use any Class-Based-View for this; it's not necessary to subclass the builtin error view.
The example project contains a ready to use example of this; uncomment the `SAML_IDP_ERROR_VIEW_CLASS` setting and it will use a custom view with custom template.


Multi Factor Authentication support
===================================

There are three main components to adding multiple factor support.


1. Subclass djangosaml2idp.processors.BaseProcessor as outlined above. You will need to override the `enable_multifactor()` method to check whether or not multifactor should be enabled for a user. (If it should allways be enabled for all users simply hard code to True). By default it unconditionally returns False and no multifactor is enforced.

2. Sublass the `djangosaml2idp.views.ProcessMultiFactorView` view to make the appropriate calls for your environment. Implement your custom verification logic in the `multifactor_is_valid` method: this could call a helper script, an internal SMS triggering service, a data source only the IdP can access or an external second factor provider (e.g. Symantec VIP). By default this view will log that it was called then redirect.

3. Add an entry to settings.py with a string representing the path to your multifactor view. The first package should be the app name:
`SAML_IDP_MULTIFACTOR_VIEW = "this.is.the.path.to.your.multifactor.view`


Running the test suite
======================
Install the dev dependencies in ``requirements-dev.txt``::

  pip install -r requirements-dev.txt

Run the test suite from the project root::

  tox -e format  # to run linting
  tox -e py3.7-django3.0  # to run the tests
  tox -e typing  # to run typechecking, this is allowed to fail

Tests will be ran using CI when opening a merge request as well.


Example project
---------------
The directory ``example_project`` contains a barebone demo setup to demonstrate the login-logout functionality.
It consists of a Service Provider implemented with `djangosaml2 <https://github.com/knaperek/djangosaml2/>`_ and an Identity Provider using ``djangosaml2idp``.
The readme in that folder contains more information on how to run it.
