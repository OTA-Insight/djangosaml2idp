import base64
import copy
import datetime
import logging
import xml
from urllib import parse

import pytest
from django.contrib.auth import authenticate, get_user_model, login, logout
from django.contrib.sessions.backends.db import SessionStore
from django.core.exceptions import (ImproperlyConfigured, PermissionDenied,
                                    ValidationError)
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.utils import timezone
from saml2 import saml
from saml2.client import Saml2Client
from saml2.config import SPConfig
from saml2.samlp import Response

from djangosaml2idp.models import ServiceProvider
from djangosaml2idp.processors import BaseProcessor
from djangosaml2idp.utils import encode_saml
from djangosaml2idp.views import (BINDING_HTTP_POST, BINDING_HTTP_REDIRECT,
                                  IdPHandlerViewMixin, LoginProcessView,
                                  LogoutProcessView, ProcessMultiFactorView,
                                  SSOInitView, get_multifactor, metadata,
                                  sso_entry, store_params_in_session)

logger = logging.getLogger(__name__)

User = get_user_model()

FILE_PREFIX = "tests/"

expected_result_file = open(FILE_PREFIX + "xml/min/request/sample_saml_request_minimal.xml")
expected_result = expected_result_file.readline()
expected_result_pretty = xml.dom.minidom.parseString(expected_result).toprettyxml()
expected_result_file.close()

sp_metadata_xml_file = open(FILE_PREFIX + "xml/metadata/sp_metadata.xml")
sp_metadata_xml = ''.join(sp_metadata_xml_file.readlines())
sp_metadata_xml_file.close()

sample_get_request = HttpRequest()
sample_get_request.method = 'GET'
sample_get_request.session = {}
sample_get_request.GET = {
    'SAMLRequest': encode_saml(expected_result),
    'RelayState': 'Test Relay State'
}


def get_logged_in_request():
    request = HttpRequest()
    request.session = SessionStore()
    username = "user1"
    password = "bar"
    User.objects.create_user(username=username, password=password)
    user = authenticate(username=username, password=password)
    if user is not None:
        login(request, user)
    request.method = 'GET'
    request.user = user
    return request


sp_conf_dict = {
    "entityid": "test_generic_sp",
    "service": {
        "sp": {
                'name_id_format': saml.NAMEID_FORMAT_UNSPECIFIED,
                'endpoints': {
                    # url and binding to the assertion consumer service view
                    # do not change the binding or service name
                    'assertion_consumer_service': [
                        ('http://localhost:8000/saml2/acs/',
                         BINDING_HTTP_POST),
                    ],
                    # url and binding to the single logout service view
                    # do not change the binding or service name
                    'single_logout_service': [
                        ('http://localhost:8000/saml2/ls/',
                         BINDING_HTTP_REDIRECT),
                        ('http://localhost:8000/saml2/ls/post',
                         BINDING_HTTP_POST),
                    ],
                },
            'idp': {
                    "test_generic_idp": {}
                }
        }
    },
    "metadata": {
        "local": ["tests/xml/metadata/idp_metadata.xml"]
    }
}

SP_TESTING_CONFIGS = {
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
    }
}


def get_saml_login_request(binding=BINDING_HTTP_REDIRECT):
    conf = SPConfig()
    conf.load(copy.deepcopy(sp_conf_dict))
    client = Saml2Client(conf)
    if binding == BINDING_HTTP_REDIRECT:
        session_id, result = client.prepare_for_authenticate(
            entityid="test_generic_idp",
            relay_state="",
            binding=binding,
        )
        return parse.parse_qs(parse.urlparse(result['headers'][0][1]).query)['SAMLRequest'][0]
    elif binding == BINDING_HTTP_POST:
        session_id, request_xml = client.create_authn_request(
            "http://localhost:9000/idp/sso/post",
            binding=binding)
    return base64.b64encode(bytes(request_xml, 'UTF-8'))


def get_saml_logout_request(id="Request ID", format=saml.NAMEID_FORMAT_UNSPECIFIED, name_id="user1"):
    xml_template = """<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{}" Version="2.0" IssueInstant="{}" Destination="{}"><saml:Issuer>{}</saml:Issuer><saml:NameID SPNameQualifier="{}metadata.php" Format="{}">{}</saml:NameID></samlp:LogoutRequest>""".format(
        id, timezone.now().strftime("%Y-%m-%dT%H:%M:%SZ"), "http://localhost:9000/idp/slo/redirect", "test_generic_sp", "test_generic_sp", format, name_id
    )
    return encode_saml(xml_template, use_zlib=True)


class CustomProcessor(BaseProcessor):
    pass


class CustomProcessorNoAccess(BaseProcessor):
    def has_access(self, request):
        return False


class CustomMultifactorView(ProcessMultiFactorView):
    def get(self, request, *args, **kwargs):
        return HttpResponse("")


class TestStoreParamsInSession:
    def test_works_correctly_with_get(self):
        store_params_in_session(sample_get_request)
        expected_session = {
            'Binding': BINDING_HTTP_REDIRECT,
            'SAMLRequest': encode_saml(expected_result),
            'RelayState': 'Test Relay State'
        }
        assert all(item in sample_get_request.session.items() for item in expected_session.items())

    def test_works_correctly_with_post(self):
        request = HttpRequest()
        request.method = 'POST'
        request.session = {}
        request.POST = {
            'SAMLRequest': encode_saml(expected_result),
            'RelayState': 'Test Relay State'
        }
        store_params_in_session(request)
        expected_session = {
            'Binding': BINDING_HTTP_POST,
            'SAMLRequest': encode_saml(expected_result),
            'RelayState': 'Test Relay State'
        }
        assert all(item in request.session.items() for item in expected_session.items())

    def test_doesnt_work_if_samlrequest_not_in_params(self):
        request = HttpRequest()
        request.method = 'GET'
        request.session = {}

        with pytest.raises(ValidationError):
            store_params_in_session(request)


class TestSSOEntry:
    def test_sso_entry_redirects(self):
        response = sso_entry(sample_get_request)
        assert isinstance(response, HttpResponseRedirect)

    def test_sso_entry_redirects_to_right_path(self):
        response = sso_entry(sample_get_request)
        assert response.url == '/login/process/'

    def test_sso_entry_returns_bad_request_if_no_samlrequest(self):
        del sample_get_request.GET['SAMLRequest']

        response = sso_entry(sample_get_request)
        assert response.status_code == 400


class TestIdPHandlerViewMixin:
    @pytest.mark.django_db
    def test_set_sp_errors_if_sp_not_defined(self):
        mixin = IdPHandlerViewMixin()

        with pytest.raises(ImproperlyConfigured):
            mixin.get_sp_config('this_sp_does_not_exist')

    @pytest.mark.django_db
    def test_set_sp_works_if_sp_defined(self, settings):
        ServiceProvider.objects.create(entity_id='test_generic_sp', local_metadata=sp_metadata_xml)

        sp = IdPHandlerViewMixin().get_sp_config('test_generic_sp')

        assert sp._processor == SP_TESTING_CONFIGS['test_generic_sp']['processor']
        assert sp.attribute_mapping == SP_TESTING_CONFIGS['test_generic_sp']['attribute_mapping']

    @pytest.mark.django_db
    def test_set_processor_errors_if_processor_cannot_be_loaded(self):
        ServiceProvider.objects.create(entity_id='test_sp_with_bad_processor', local_metadata=sp_metadata_xml, _processor='this.does.not.exist')
        sp = IdPHandlerViewMixin().get_sp_config('test_sp_with_bad_processor')

        with pytest.raises(Exception):
            _ = sp.processor

    @pytest.mark.django_db
    def test_set_processor_defaults_to_base_processor(self):
        ServiceProvider.objects.create(entity_id='test_sp_with_no_processor', local_metadata=sp_metadata_xml, _attribute_mapping='{}')

        sp = IdPHandlerViewMixin().get_sp_config('test_sp_with_no_processor')

        assert isinstance(sp.processor, BaseProcessor)

    @pytest.mark.django_db
    def test_get_processor_loads_custom_processor(self):
        ServiceProvider.objects.create(entity_id='test_sp_with_custom_processor', local_metadata=sp_metadata_xml, _processor='tests.test_views.CustomProcessor')

        sp = IdPHandlerViewMixin().get_sp_config('test_sp_with_custom_processor')

        assert isinstance(sp.processor, CustomProcessor)

    def test_get_authn_returns_correctly_when_no_req_info(self):
        assert IdPHandlerViewMixin().get_authn() == {
            'authn_auth': '',
            'class_ref': 'urn:oasis:names:tc:SAML:2.0:ac:classes:Password',
            'level': 0,
            'method': ''
        }

    @pytest.mark.django_db
    def test_check_access_works(self):
        ServiceProvider.objects.create(entity_id='test_generic_sp', local_metadata=sp_metadata_xml)

        mixin = IdPHandlerViewMixin()
        sp = mixin.get_sp_config('test_generic_sp')
        processor = sp.processor
        mixin.check_access(processor, HttpRequest())

    @pytest.mark.django_db
    def test_check_access_fails_when_it_should(self):
        ServiceProvider.objects.create(entity_id='test_sp_with_custom_processor_that_doesnt_allow_access', local_metadata=sp_metadata_xml, _processor='tests.test_views.CustomProcessorNoAccess')

        mixin = IdPHandlerViewMixin()
        sp = mixin.get_sp_config('test_sp_with_custom_processor_that_doesnt_allow_access')
        processor = sp.processor
        with pytest.raises(PermissionDenied):
            mixin.check_access(processor, HttpRequest())

    @pytest.mark.django_db
    def test_build_authn_response(self):
        ServiceProvider.objects.create(entity_id='test_generic_sp', local_metadata=sp_metadata_xml)

        mixin = IdPHandlerViewMixin()
        sp = mixin.get_sp_config('test_generic_sp')
        user = User()
        authn = mixin.get_authn()
        resp_args = {
            "in_response_to": "SP_Initiated_Login",
            "destination": "https://sp.example.com/SAML2",
        }
        assert isinstance(mixin.build_authn_response(user, authn, resp_args, sp), Response)

    @pytest.mark.django_db
    def test_create_html_response_with_post(self):
        html_response = IdPHandlerViewMixin().create_html_response(HttpRequest(), BINDING_HTTP_POST, "SAMLResponse", "https://sp.example.com/SAML2", "")
        assert isinstance(html_response['data'], str)

    @pytest.mark.django_db
    def test_create_html_response_with_get(self):
        mixin = IdPHandlerViewMixin()
        html_response = mixin.create_html_response(HttpRequest(), BINDING_HTTP_REDIRECT, "SAMLResponse", "https://sp.example.com/SAML2", "")
        assert isinstance(html_response['data'], str)

    @pytest.mark.django_db
    def test_render_response_with_no_processor_and_post_binding(self):
        html_response = {
            "type": "POST",
            "data": "<html></html>"
        }
        response = IdPHandlerViewMixin().render_response(HttpRequest(), html_response)

        assert response.content.decode() == "<html></html>"
        assert isinstance(response, HttpResponse)

    @pytest.mark.django_db
    def compile_data_for_render_response(self):
        ServiceProvider.objects.create(entity_id='test_generic_sp', local_metadata=sp_metadata_xml)

        mixin = IdPHandlerViewMixin()
        _ = mixin.get_sp_config("test_generic_sp")

        user = User.objects.create()
        user.email = "test@gmail.com",
        user.first_name = 'First Name',
        user.last_name = 'Last Name',
        user.is_staff = True
        user.is_superuser = False

        request = HttpRequest()
        request.user = user
        request.session = {}

        html_response = {
            "type": "POST",
            "data": "<html></html>"
        }
        return mixin, request, html_response

    @pytest.mark.django_db
    def test_render_response_with_no_processor_and_redirect_binding(self):
        html_response = {
            "type": "REDIRECT",
            "data": "https://example.com"
        }
        response = IdPHandlerViewMixin().render_response(HttpRequest(), html_response)

        assert response.url == "https://example.com"
        assert isinstance(response, HttpResponseRedirect)

    @pytest.mark.django_db
    def test_render_response_constructs_request_session_properly(self):
        (mixin, request, html_response) = self.compile_data_for_render_response()

        expected_session = {
            "saml_data": html_response
        }

        mixin.render_response(request, html_response, mixin.get_sp_config('test_generic_sp').processor)

        assert all(item in request.session.items() for item in expected_session.items())

    @pytest.mark.django_db
    def test_redirects_multifactor_if_relevant(self):
        (mixin, request, html_response) = self.compile_data_for_render_response()

        def multifactor(self, user):
            return True

        # Bind enable_multifactor being true to mixin processor.
        processor = mixin.get_sp_config('test_generic_sp').processor
        processor.enable_multifactor = multifactor.__get__(processor)
        response = mixin.render_response(request, html_response, processor)
        assert isinstance(response, HttpResponseRedirect)
        assert response.url == "/login/process_multi_factor/"


class TestLoginProcessView:
    @pytest.mark.django_db
    def test_requires_authentication(self):
        request = get_logged_in_request()
        logout(request)

        response = LoginProcessView.as_view()(request)
        assert isinstance(response, HttpResponseRedirect)
        assert response.url == '/accounts/login/?next='

    @pytest.mark.django_db
    def test_goes_through_normally_redirect(self):
        ServiceProvider.objects.create(entity_id='test_generic_sp', local_metadata=sp_metadata_xml)

        request = get_logged_in_request()
        # Simulating having already gone through sso_entry
        request.session.update({
            "SAMLRequest": get_saml_login_request(),
            "RelayState": "",
            "Binding": BINDING_HTTP_REDIRECT
        })

        response = LoginProcessView.as_view()(request)
        assert isinstance(response, HttpResponse)

    @pytest.mark.django_db
    def test_goes_through_normally_post(self):
        ServiceProvider.objects.create(entity_id='test_generic_sp', local_metadata=sp_metadata_xml)

        request = get_logged_in_request()
        request.session.update({
            "SAMLRequest": get_saml_login_request(),
            "RelayState": "",
            "Binding": BINDING_HTTP_POST
        })

        response = LoginProcessView.as_view()(request)
        assert isinstance(response, HttpResponse)


class TestIdpInitiatedFlow:
    @pytest.mark.django_db
    def test_goes_through_correctly_get(self):
        request = get_logged_in_request()
        request.GET['sp'] = "test_generic_sp"

        response = SSOInitView.as_view()(request)
        assert isinstance(response, HttpResponse)

    @pytest.mark.django_db
    def test_goes_through_correctly_post(self):
        request = get_logged_in_request()
        request.method = 'POST'
        request.POST['sp'] = "test_generic_sp"

        response = SSOInitView.as_view()(request)
        assert isinstance(response, HttpResponse)

    @pytest.mark.django_db
    def test_requires_authentication(self):
        request = get_logged_in_request()

        logout(request)
        response = SSOInitView.as_view()(request)
        assert isinstance(response, HttpResponseRedirect)
        assert response.url == '/accounts/login/?next='


class TestGetMultifactor:
    @pytest.mark.django_db
    def test_loads_data_when_appropriate_with_post(self):
        # We only really need to test one aspect. If the system doesn't work, it won't work.
        request = get_logged_in_request()
        request.session['saml_data'] = {
            "type": "POST",
            "data": "<html></html>",
        }
        response = get_multifactor(request)
        assert isinstance(response, HttpResponse)
        assert response.content == '<html></html>'.encode()

    @pytest.mark.django_db
    def test_works_with_replacement(self, settings):
        settings.SAML_IDP_MULTIFACTOR_VIEW = "tests.test_views.CustomMultifactorView"
        request = get_logged_in_request()
        response = get_multifactor(request)
        assert isinstance(response, HttpResponse)
        assert response.content == b""


class TestMultifactor:
    @pytest.mark.django_db
    def test_multifactor_is_valid_returns_true_by_default(self):
        request = get_logged_in_request()
        assert ProcessMultiFactorView().multifactor_is_valid(request) is True

    @pytest.mark.django_db
    def test_loads_data_when_appropriate_with_post(self):
        request = get_logged_in_request()
        request.session['saml_data'] = {
            "type": "POST",
            "data": "<html></html>",
        }
        response = ProcessMultiFactorView.as_view()(request)
        assert isinstance(response, HttpResponse)
        assert response.content == '<html></html>'.encode()

    @pytest.mark.django_db
    def test_loads_data_when_appropriate_with_redirect(self):
        request = get_logged_in_request()
        request.session['saml_data'] = {
            "type": "REDIRECT",
            "data": "https://example.com",
        }
        response = ProcessMultiFactorView.as_view()(request)
        assert isinstance(response, HttpResponseRedirect)
        assert response.url == "https://example.com"

    @pytest.mark.django_db
    def test_get_logs_out_if_multifactor_invalid(self):
        request = get_logged_in_request()

        def valid(self, request):
            return False
        a = ProcessMultiFactorView.multifactor_is_valid
        ProcessMultiFactorView.multifactor_is_valid = valid
        with pytest.raises(PermissionDenied):
            ProcessMultiFactorView.as_view()(request)
        ProcessMultiFactorView.multifactor_is_valid = a


class TestLogoutProcessView:
    @pytest.mark.django_db
    def test_slo_view_works_properly_redirect(self):
        ServiceProvider.objects.create(entity_id='test_generic_sp', local_metadata=sp_metadata_xml)

        request = get_logged_in_request()
        request.GET['SAMLRequest'] = get_saml_logout_request()

        response = LogoutProcessView.as_view()(request)

        assert isinstance(response, HttpResponse)


class TestMetadata:
    @pytest.mark.django_db
    def test_metadata_works_correctly(self):
        response = metadata(HttpRequest())
        assert isinstance(response, HttpResponse)
        assert response.charset == 'utf8'
        assert response.status_code == 200
        assert 'Location="http://localhost:9000/idp' in response.content.decode()
