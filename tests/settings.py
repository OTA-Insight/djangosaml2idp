import os
import saml2
from saml2.saml import NAMEID_FORMAT_UNSPECIFIED, NAMEID_FORMAT_EMAILADDRESS

PROJECT_ROOT = os.getcwd()

SECRET_KEY = 'q+0vb%)c7c%&kl&jcca^6n7$3q4ktle9i28t(fd&qh28%l-%58'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': './idptest.sqlite',
        'USER': '',
        'PASSWORD': '',
        'HOST': '',
        'PORT': '',
    }
}


TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

INSTALLED_APPS = (
    'django.contrib.auth',
    'django.contrib.admin',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'djangosaml2idp',
    'tests',
)

ROOT_URLCONF = 'tests.urls'

BASE_URL = 'http://localhost:9000/idp'

SAML_AUTHN_SIGN_ALG = saml2.xmldsig.SIG_RSA_SHA256
SAML_AUTHN_DIGEST_ALG = saml2.xmldsig.DIGEST_SHA256

SAML_IDP_CONFIG = {
    'service': {
        'idp': {
            'endpoints': {
                'single_sign_on_service': [
                    ('%s/sso/post' % BASE_URL, saml2.BINDING_HTTP_POST),
                    ('%s/sso/redirect' % BASE_URL, saml2.BINDING_HTTP_REDIRECT),
                ],
            },
            'name_id_format': [NAMEID_FORMAT_EMAILADDRESS, NAMEID_FORMAT_UNSPECIFIED],
        }
    },

    'metadata': {
        'local': ['tests/xml/metadata/sp_metadata.xml'],
    }
}
