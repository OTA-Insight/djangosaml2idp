from datetime import timedelta

import pytest
import requests_mock
from django.utils import timezone

from djangosaml2idp.models import ServiceProvider

XML = """<ns0:EntityDescriptor xmlns:ns0="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ns1="urn:oasis:names:tc:SAML:metadata:algsupport" xmlns:ns2="http://www.w3.org/2000/09/xmldsig#" entityID="test_generic_sp" validUntil="2021-02-14T17:43:34Z"></ns0:EntityDescriptor>"""


class TestServiceProvider:
    def test_refresh_meta_data_returns_false_on_model_state(self):
        instance = ServiceProvider(
            local_metadata=timezone.now(),
            metadata_expiration_dt=timezone.now() + timedelta(hours=1),
        )
        assert instance.refresh_metadata() is False

    @pytest.mark.parametrize(
        "instance",
        (
            pytest.param(
                ServiceProvider(metadata_expiration_dt=timezone.now()),
                marks=pytest.mark.xfail(reason="Case self.local_metadata is falsy"),
            ),
            ServiceProvider(
                local_metadata=XML
            ),  # Case metadata_expiration_dt is not set
            ServiceProvider(
                local_metadata=XML,
                metadata_expiration_dt=timezone.now() - timedelta(hours=1),
            ),  # Case metadata_expiration_dt expired
        ),
    )
    def test_refresh_meta_data_returns_true_on_model_state(self, instance):
        assert instance.refresh_metadata() is True

    def test_refresh_meta_data_returns_true_on_force_refresh(self):
        sp = ServiceProvider(
            local_metadata=XML,
            metadata_expiration_dt=timezone.now() + timedelta(hours=1),
        )

        assert sp.refresh_metadata(True) is True

    def test_refresh_metadata_updates_metadata_expiration_dt_from_remote(self):
        sp = ServiceProvider(
            metadata_expiration_dt=timezone.now(),
            remote_metadata_url="http://someremote",
        )
        with requests_mock.mock() as m:
            m.get(sp.remote_metadata_url, text=XML)
            refreshed = sp.refresh_metadata()

        assert refreshed
        assert sp.local_metadata == XML
