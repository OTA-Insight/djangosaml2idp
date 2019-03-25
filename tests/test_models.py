import pytest

from datetime import timedelta
from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured
from django.db import IntegrityError
from django.utils import timezone
from djangosaml2idp.models import AgreementRecord

User = get_user_model()


class TestAgreementRecord:
    @pytest.mark.django_db
    def test_raises_exception_if_no_sp_config(self, settings):
        del settings.SAML_IDP_SPCONFIG
        user = User.objects.create()

        with pytest.raises(ImproperlyConfigured):
            AgreementRecord.objects.create(user=user, sp_entity_id="literally_anything")

    @pytest.mark.django_db
    def test_raises_error_if_sp_entity_id_invalid(self):
        user = User.objects.create()

        with pytest.raises(ImproperlyConfigured):
            AgreementRecord.objects.create(user=user, sp_entity_id="id_not_in_settings")

    @pytest.mark.django_db
    def test_cant_create_2_records_for_same_sp_and_same_user(self):
        user = User.objects.create()
        AgreementRecord.objects.create(user=user, sp_entity_id="test_generic_sp")

        with pytest.raises(IntegrityError):
            AgreementRecord.objects.create(user=user, sp_entity_id="test_generic_sp")

    @pytest.mark.django_db
    def test_wants_more_attrs_returns_true_if_actually_true(self):
        user = User.objects.create()
        record = AgreementRecord.objects.create(user=user, sp_entity_id="test_generic_sp", attrs="name,email,password")

        assert record.wants_more_attrs("name,email,password,telephone") is True

    @pytest.mark.django_db
    def test_wants_more_attr_returns_false_if_less_attrs_requested_but_no_new_attrs(self):
        user = User.objects.create()
        record = AgreementRecord.objects.create(user=user, sp_entity_id="test_generic_sp", attrs="name,email,password")

        assert record.wants_more_attrs("name") is False

    @pytest.mark.django_db
    def test_expired_works_for_expired(self):
        expired_time = timezone.now() - timedelta(days=400)
        user = User.objects.create()
        record = AgreementRecord.objects.create(user=user, sp_entity_id="test_generic_sp", date=expired_time)

        assert record.is_expired() is True

    @pytest.mark.django_db
    def test_expired_works_for_non_expired(self):
        nonexpired_time = timezone.now() - timedelta(days=300)
        user = User.objects.create()
        record = AgreementRecord.objects.create(user=user, sp_entity_id="test_generic_sp", date=nonexpired_time)

        assert record.is_expired() is False

    @pytest.mark.django_db
    def test_not_expired_if_no_expiration_time(self):
        user = User.objects.create()
        record = AgreementRecord.objects.create(user=user, sp_entity_id="test_sp_with_no_expiration")

        assert record.is_expired() is False

