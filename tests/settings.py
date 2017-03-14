from __future__ import absolute_import, division, print_function, unicode_literals

import os
PROJECT_ROOT = os.getcwd()

SECRET_KEY = 'q+0vb%)c7c%&kl&jcca^6n7$3q4ktle9i28t(fd&qh28%l-%58'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3', # Add 'postgresql_psycopg2', 'postgresql', 'mysql', 'sqlite3' or 'oracle'.
        'NAME': './idptest.sqlite',                      # Or path to database file if using sqlite3.
        'USER': '',                      # Not used with sqlite3.
        'PASSWORD': '',                  # Not used with sqlite3.
        'HOST': '',                      # Set to empty string for localhost. Not used with sqlite3.
        'PORT': '',                      # Set to empty string for default. Not used with sqlite3.
    }
}

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
    },
]

INSTALLED_APPS = (
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'djangosaml2idp',
    'tests',
)

ROOT_URLCONF = 'tests.urls'

LOGIN_REDIRECT_URL = '/idp/sso/post/response/preview/'

# SAML2IDP metadata settings
SAML2IDP_CONFIG = {
    'autosubmit': False,
    'issuer': 'http://127.0.0.1:8000',
    'signing': True,
    'certificate_file': PROJECT_ROOT + '/tests/keys/sample/sample-certificate.pem',
    'private_key_file': PROJECT_ROOT + '/tests/keys/sample/sample-private-key.pem',
}

demoSpConfig = {
    'acs_url': 'http://127.0.0.1:9000/sp/acs/',
    'processor': 'djangosaml2idp.processors.Processor',
    'links': [ # a list of (resource, pattern) tuples, or a {resource: pattern} dict
        #NOTE: This should still work, due to the "simple" 'login_init' URL in urls.py:
        #TEST BY BROWSING TO: http://127.0.0.1:8000/sp/test/
        ('deeplink', 'http://127.0.0.1:9000/sp/%s/'),
        # The following are "new" deeplink mappings that let you specify more than one capture group:
        # This is equivalent to the above, using the 'new' deeplink mapping:
        #TEST BY BROWSING TO: http://127.0.0.1:8000/sp/test/
        (r'deeplink/(?P<target>\w+)', 'http://127.0.0.1:9000/sp/%(target)s/'),
        # Using two capture groups:
        #TEST BY BROWSING TO: http://127.0.0.1:8000/sp/test/
        (r'deeplink/(?P<target>\w+)/(?P<page>\w+)', 'http://127.0.0.1:9000/%(target)s/%(page)s/'),
        # Deeplink to a resource that requires query parameters:
        #NOTE: In the pattern, always use %(variable)s, because the captured
        # parameters will always be in unicode.
        #TEST BY BROWSING TO: http://127.0.0.1:8000/sp/test/123/
        (r'deeplink/(?P<target>\w+)/(?P<page>\w+)/(?P<param>\d+)',
            'http://127.0.0.1:9000/%(target)s/%(page)s/?param=%(param)s'),
    ],
}
attrSpConfig = {
    'acs_url': 'http://127.0.0.1:9000/sp/acs/',
    'processor': 'djangosaml2idp.processors.AttributeProcessor',
    'links': {
        'attr': 'http://127.0.0.1:9000/sp/%s/',
    },
}
SAML2IDP_REMOTES = {
    # Group of SP CONFIGs.
    # friendlyname: SP config
    'attr_demo': attrSpConfig,
    'demo': demoSpConfig,
}

# Setup logging.
import logging
logging.basicConfig(filename=PROJECT_ROOT + '/saml2idp.log', format='%(asctime)s: %(message)s', level=logging.DEBUG)
logging.info('Logging setup.')
