import json
from datetime import timedelta
from unittest import mock

import arrow
import pytest
from django.utils import timezone
from saml2 import xmldsig

import requests_mock
from djangosaml2idp.idp import IDP
from djangosaml2idp.models import DEFAULT_ATTRIBUTE_MAPPING, ServiceProvider

from .testing_utilities import mocked_requests_get

future_dt = arrow.get().shift(days=30)
expired_dt = arrow.get().shift(days=-30)

VALID_XML = f"""<ns0:EntityDescriptor xmlns:ns0="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ns1="urn:oasis:names:tc:SAML:metadata:algsupport" xmlns:ns2="http://www.w3.org/2000/09/xmldsig#" entityID="test_generic_sp" validUntil="{future_dt.isoformat()}"></ns0:EntityDescriptor>"""
EXPIRED_XML = f"""<ns0:EntityDescriptor xmlns:ns0="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ns1="urn:oasis:names:tc:SAML:metadata:algsupport" xmlns:ns2="http://www.w3.org/2000/09/xmldsig#" entityID="test_generic_sp" validUntil="{expired_dt.isoformat()}"></ns0:EntityDescriptor>"""


class TestServiceProvider:
    def test_prettyname_sp(self):
        instance = ServiceProvider(entity_id='dummy_sp')
        assert str(instance) == 'dummy_sp'
        instance = ServiceProvider(entity_id='dummy_sp', pretty_name='Dummy SP')
        assert str(instance) == 'Dummy SP (dummy_sp)'

    def test_property_attribute_mapping(self):
        instance = ServiceProvider(_attribute_mapping=None)
        assert instance.attribute_mapping == DEFAULT_ATTRIBUTE_MAPPING
        instance = ServiceProvider(_attribute_mapping='{"custom_key": "custom_value"}')
        assert instance.attribute_mapping == {"custom_key": "custom_value"}

    def test_property_sign_response(self):
        instance = ServiceProvider(_sign_response=None)
        assert instance.sign_response == getattr(IDP.load().config, "sign_response", False)
        instance = ServiceProvider(_sign_response=True)
        assert instance.sign_response == True

    def test_property_sign_assertion(self):
        instance = ServiceProvider(_sign_assertion=None)
        assert instance.sign_assertion == getattr(IDP.load().config, "sign_assertion", False)
        instance = ServiceProvider(_sign_assertion=True)
        assert instance.sign_assertion == True

    def test_property_encrypt_saml_responses(self):
        instance = ServiceProvider(_encrypt_saml_responses=None)
        assert instance.encrypt_saml_responses == getattr(IDP.load().config, "SAML_ENCRYPT_AUTHN_RESPONSE", False)
        instance = ServiceProvider(_encrypt_saml_responses=True)
        assert instance.encrypt_saml_responses == True

    def test_property_signing_algorithm(self):
        instance = ServiceProvider(_signing_algorithm=None)
        assert instance.signing_algorithm == getattr(IDP.load().config, "SAML_AUTHN_SIGN_ALG", xmldsig.SIG_RSA_SHA256)
        instance = ServiceProvider(_signing_algorithm='dummy_value')
        assert instance.signing_algorithm == 'dummy_value'

    def test_property_digest_algorithm(self):
        instance = ServiceProvider(_digest_algorithm=None)
        assert instance.digest_algorithm == getattr(IDP.load().config, "SAML_AUTHN_DIGEST_ALG", xmldsig.DIGEST_SHA256)
        instance = ServiceProvider(_digest_algorithm='dummy_value')
        assert instance.digest_algorithm == 'dummy_value'

    def test_resulting_config_representation_successful_marshalling(self):
        instance = ServiceProvider(entity_id='dummy_sp', _sign_assertion=True, _sign_response=True, _encrypt_saml_responses=True,
                                    _digest_algorithm='dummy_digest', _signing_algorithm='dummy_sign')

        resulting_config_as_str = instance.resulting_config
        resulting_config_as_dict = json.loads(resulting_config_as_str.replace('&nbsp;', '').replace('<br>', ''))
        assert resulting_config_as_dict == {
                'entity_id': 'dummy_sp',
                'attribute_mapping': DEFAULT_ATTRIBUTE_MAPPING,
                'nameid_field': 'username',
                'sign_response': True,
                'sign_assertion': True,
                'encrypt_saml_responses': True,
                'signing_algorithm': 'dummy_sign',
                'digest_algorithm': 'dummy_digest',
            }

    def test_resulting_config_representation_failure_marshalling(self):
        instance = ServiceProvider(entity_id=set([1, 2, 3]))

        resulting_config_as_str = instance.resulting_config
        assert 'Could not render config: ' in resulting_config_as_str

    def test_refresh_meta_data_returns_false_on_model_state(self):
        instance = ServiceProvider(
            local_metadata=timezone.now(),
            metadata_expiration_dt=timezone.now() + timedelta(hours=1),
        )
        assert instance.refresh_metadata() is False

    @pytest.mark.django_db
    def test_should_refresh_on_changed_local_metadata(self, sp_metadata_xml):
        ServiceProvider.objects.create(entity_id='entity-id', local_metadata=sp_metadata_xml)
        instance = ServiceProvider.objects.get(entity_id='entity-id')
        # By default, no refresh necessary upon loading
        assert instance._should_refresh() is False
        # After modifying the local_metadata, refresh is necessary
        instance.local_metadata = EXPIRED_XML
        assert instance._should_refresh() is True

    @pytest.mark.django_db
    @mock.patch('requests.get', side_effect=mocked_requests_get)
    def test_should_refresh_on_changed_remote_metadata_url(self, mock_get, sp_metadata_xml):
        ServiceProvider.objects.create(entity_id='entity-id', remote_metadata_url='https://ok', local_metadata=sp_metadata_xml)
        instance = ServiceProvider.objects.get(entity_id='entity-id')
        # By default, no refresh necessary upon loading
        assert instance._should_refresh() is False
        # After modifying the remote_metadata_url, refresh is necessary
        instance.remote_metadata_url = 'https://new-ok'
        assert instance._should_refresh() is True

    @pytest.mark.parametrize(
        "instance",
        (
            ServiceProvider(
                metadata_expiration_dt=timezone.now(),
                remote_metadata_url="http://someremote",
                # Case self.local_metadata is falsy
            ),
            ServiceProvider(
                local_metadata=VALID_XML
            ),  # Case metadata_expiration_dt is not set, valid local_metadata
            ServiceProvider(
                local_metadata=VALID_XML,
                metadata_expiration_dt=timezone.now() - timedelta(hours=1),
            ),  # Case metadata_expiration_dt expired, valid local_metadata
        ),
    )
    def test_refresh_meta_data_succesful_returns_true_on_model_state(self, instance):
        if instance.remote_metadata_url:
            with requests_mock.mock() as m:
                m.get(instance.remote_metadata_url, text=VALID_XML)
                refreshed = instance.refresh_metadata()
        else:
            refreshed = instance.refresh_metadata()

        assert refreshed

    @pytest.mark.parametrize(
        "instance",
        (
            ServiceProvider(
                metadata_expiration_dt=timezone.now(),
                remote_metadata_url="http://not_found",
                # Case self.local_metadata is falsy, no valid remote
            ),
            ServiceProvider(
                local_metadata=''
            ),  # Case neither local_metadata nor remote metadata
            ServiceProvider(
                metadata_expiration_dt=timezone.now(),
                remote_metadata_url="http://expired_remote",
                # Case self.local_metadata is falsy, expired dt in remote metadata
            ),
            ServiceProvider(
                local_metadata=VALID_XML[:100]
            ),  # Case metadata_expiration_dt is not set, invalid local_metadata content
            ServiceProvider(
                local_metadata=EXPIRED_XML
            ),  # Case metadata_expiration_dt is not set, expired local_metadata content
            ServiceProvider(
                local_metadata=VALID_XML[:100],
                metadata_expiration_dt=timezone.now() - timedelta(hours=1),
            ),  # Case metadata_expiration_dt expired, invalid local_metadata content
            ServiceProvider(
                local_metadata=EXPIRED_XML,
                metadata_expiration_dt=timezone.now() - timedelta(hours=1),
            ),  # Case metadata_expiration_dt expired, expired local_metadata content
        ),
    )
    def test_refresh_meta_data_failure_returns_false_on_model_state(self, instance):
        if instance.remote_metadata_url:
            if instance.remote_metadata_url == "http://expired_remote":
                with requests_mock.mock() as m:
                    m.get(instance.remote_metadata_url, text=EXPIRED_XML)
                    refreshed = instance.refresh_metadata()
            if instance.remote_metadata_url == "http://not_found":
                with requests_mock.mock() as m:
                    m.get(instance.remote_metadata_url, text='Notfound')
                    refreshed = instance.refresh_metadata()
        else:
            refreshed = instance.refresh_metadata()

        assert not refreshed

    def test_refresh_meta_data_returns_true_on_force_refresh(self):
        sp = ServiceProvider(
            local_metadata=EXPIRED_XML,
            metadata_expiration_dt=timezone.now() + timedelta(hours=1),
            remote_metadata_url="http://someremote",
        )

        with requests_mock.mock() as m:
            m.get(sp.remote_metadata_url, text=VALID_XML)
            refreshed = sp.refresh_metadata(True)

        assert refreshed
        assert sp.local_metadata == VALID_XML

    def test_refresh_metadata_updates_metadata_expiration_dt_from_remote(self):
        sp = ServiceProvider(
            metadata_expiration_dt=timezone.now(),
            remote_metadata_url="http://someremote",
        )
        with requests_mock.mock() as m:
            m.get(sp.remote_metadata_url, text=VALID_XML)
            refreshed = sp.refresh_metadata()

        assert refreshed
        assert sp.local_metadata == VALID_XML
