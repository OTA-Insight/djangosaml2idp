import datetime
import json
from unittest import mock

import pytest
from django.contrib.auth import get_user_model
from django.utils import timezone
from djangosaml2idp.forms import ServiceProviderAdminForm

User = get_user_model()


class TestAdminForm:

    @pytest.mark.django_db
    def test_nometadata_given(self):
        form = ServiceProviderAdminForm({})

        assert form.is_valid() is False
        assert 'Either a remote metadata URL, or a local metadata xml needs to be provided.' in form.errors['__all__']

    @pytest.mark.django_db
    @pytest.mark.parametrize('use_tz, tzinfo', [(True, timezone.utc), (False, None)])
    def test_valid_local_metadata(self, settings, sp_metadata_xml, use_tz, tzinfo):
        settings.USE_TZ = use_tz
        form = ServiceProviderAdminForm({
            'entity_id': 'entity-id',
            '_processor': 'djangosaml2idp.processors.BaseProcessor',
            'local_metadata': sp_metadata_xml,
            '_attribute_mapping': json.dumps({
                'name': 'fullName',
                'email': 'emailAddress',
                'other_setting': 'otherSetting',
                'random_method': 'randomMethodTest'
            }),
        })
        assert form.is_valid() is True
        instance = form.save()
        assert instance.remote_metadata_url == ''
        assert instance.local_metadata == sp_metadata_xml
        assert instance.metadata_expiration_dt == datetime.datetime(2099, 2, 14, 17, 43, 34, tzinfo=tzinfo)

    @pytest.mark.django_db
    def test_invalid_local_metadata(self):
        form = ServiceProviderAdminForm({
            'entity_id': 'entity-id',
            '_processor': 'djangosaml2idp.processors.BaseProcessor',
            'local_metadata': 'BOGUS DATA',
            '_attribute_mapping': json.dumps({
                'name': 'fullName',
                'email': 'emailAddress',
                'other_setting': 'otherSetting',
                'random_method': 'randomMethodTest'
            }),
        })

        assert form.is_valid() is False
        assert 'Metadata expiration dt for SP  could not be extracted from local metadata.' in form.errors['__all__']

    @pytest.mark.django_db
    @mock.patch('requests.get')
    @pytest.mark.parametrize('use_tz, tzinfo', [(True, timezone.utc), (False, None)])
    def test_valid_remote_metadata_url(self, mock_get, settings, sp_metadata_xml, use_tz, tzinfo):
        settings.USE_TZ = use_tz
        mock_get.return_value = mock.Mock(status_code=200, text=sp_metadata_xml)
        form = ServiceProviderAdminForm({
            'entity_id': 'entity-id',
            '_processor': 'djangosaml2idp.processors.BaseProcessor',
            'remote_metadata_url': 'https://ok',
            '_attribute_mapping': json.dumps({
                'name': 'fullName',
                'email': 'emailAddress',
                'other_setting': 'otherSetting',
                'random_method': 'randomMethodTest'
            }),
        })

        assert form.is_valid() is True
        instance = form.save()
        assert instance.remote_metadata_url == 'https://ok'
        assert instance.local_metadata == sp_metadata_xml
        assert instance.metadata_expiration_dt == datetime.datetime(2099, 2, 14, 17, 43, 34, tzinfo=tzinfo)

    @pytest.mark.django_db
    @mock.patch('requests.get')
    def test_invalid_remote_metadata_url(self, mock_get):
        mock_get.return_value = mock.Mock(status_code=200, text='BOGUS DATA')
        form = ServiceProviderAdminForm({
            'entity_id': 'entity-id',
            '_processor': 'djangosaml2idp.processors.BaseProcessor',
            'remote_metadata_url': 'https://ok',
            '_attribute_mapping': json.dumps({
                'name': 'fullName',
                'email': 'emailAddress',
                'other_setting': 'otherSetting',
                'random_method': 'randomMethodTest'
            }),
        })

        assert form.is_valid() is False
        assert 'Metadata for SP  could not be pulled from remote url https://ok.' in form.errors['__all__']

    @pytest.mark.django_db
    def test_metadata_invalid_not_json_parseable(self, sp_metadata_xml):
        form = ServiceProviderAdminForm({
            'entity_id': 'entity-id',
            '_processor': 'djangosaml2idp.processors.BaseProcessor',
            'local_metadata': sp_metadata_xml,
            '_attribute_mapping': 'invalid_json_content',
        })

        assert form.is_valid() is False
        assert 'The provided string could not be parsed with json.' in form.errors['_attribute_mapping'][0]

    @pytest.mark.django_db
    def test_metadata_invalid_nodict(self, sp_metadata_xml):
        form = ServiceProviderAdminForm({
            'entity_id': 'entity-id',
            '_processor': 'djangosaml2idp.processors.BaseProcessor',
            'local_metadata': sp_metadata_xml,
            '_attribute_mapping': json.dumps(''),
        })

        assert form.is_valid() is False
        assert 'The provided attribute_mapping should be a string representing a dict.' in form.errors['_attribute_mapping'][0]

    @pytest.mark.django_db
    def test_metadata_invalid_dict_wroncontent(self, sp_metadata_xml):
        form = ServiceProviderAdminForm({
            'entity_id': 'entity-id',
            '_processor': 'djangosaml2idp.processors.BaseProcessor',
            'local_metadata': sp_metadata_xml,
            '_attribute_mapping': json.dumps({
                1: 2,
            }),
        })

        assert form.is_valid() is False
        assert 'The provided attribute_mapping should be a dict with strings for both all keys and values.' in form.errors['_attribute_mapping'][0]
