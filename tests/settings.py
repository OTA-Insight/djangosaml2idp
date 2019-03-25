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

SAML_IDP_SPCONFIG = {
    'test_sp_with_no_processor': {
        'attribute_mapping': {}
    },
    'test_sp_with_bad_processor': {
        'processor': 'this.does.not.exist',
    },
    'test_sp_with_custom_processor': {
        'processor': 'tests.test_views.CustomProcessor'
    },
    'test_sp_with_custom_processor_that_doesnt_allow_access': {
        'processor': 'tests.test_views.CustomProcessorNoAccess'
    },
    'test_sp_with_no_expiration': {},
    'test_generic_sp': {
        'processor': 'djangosaml2idp.processors.BaseProcessor',
        'attribute_mapping': {
            # DJANGO: SAML
            'email': 'email',
            'first_name': 'first_name',
            'last_name': 'last_name',
            'is_staff': 'is_staff',
            'is_superuser':  'is_superuser',
        },
        'user_agreement_valid_for': 24 * 365
    }
}
