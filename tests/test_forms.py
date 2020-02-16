import json
from unittest import mock

import pytest
from django.contrib.auth import get_user_model
from .testing_utilities import mocked_requests_get
from djangosaml2idp.forms import ServiceProviderAdminForm
from djangosaml2idp.utils import extract_validuntil_from_metadata

User = get_user_model()

FILE_PREFIX = "tests/"

with open(FILE_PREFIX + "xml/metadata/sp_metadata.xml") as sp_metadata_xml_file:
    sp_metadata_xml = ''.join(sp_metadata_xml_file.readlines())


class TestAdminForm:

    @pytest.mark.django_db
    def test_nometadata_given(self):
        form = ServiceProviderAdminForm({})

        assert form.is_valid() is False
        assert 'Either a remote metadata URL, or a local metadata xml needs to be provided.' in form.errors['__all__']

    @pytest.mark.django_db
    def test_valid(self):
        form = ServiceProviderAdminForm({
            'entity_id': 'entity-id',
            '_processor': 'djangosaml2idp.processors.BaseProcessor',
            'local_metadata': sp_metadata_xml,
            'metadata_expiration_dt': extract_validuntil_from_metadata(sp_metadata_xml),
            '_attribute_mapping': json.dumps({
                'name': 'fullName',
                'email': 'emailAddress',
                'other_setting': 'otherSetting',
                'random_method': 'randomMethodTest'
            }),
        })

        assert form.is_valid() is True

    @pytest.mark.django_db
    @mock.patch('requests.get', side_effect=mocked_requests_get)
    def test_valid_remote_metadata_url(self, mock_get):
        form = ServiceProviderAdminForm({
            'entity_id': 'entity-id',
            '_processor': 'djangosaml2idp.processors.BaseProcessor',
            'local_metadata': sp_metadata_xml,
            'remote_metadata_url': 'https://ok',
            'metadata_expiration_dt': extract_validuntil_from_metadata(sp_metadata_xml),
            '_attribute_mapping': json.dumps({
                'name': 'fullName',
                'email': 'emailAddress',
                'other_setting': 'otherSetting',
                'random_method': 'randomMethodTest'
            }),
        })

        assert form.is_valid() is True

    @pytest.mark.django_db
    def test_metadata_invalid_not_json_parseable(self):
        form = ServiceProviderAdminForm({
            'entity_id': 'entity-id',
            '_processor': 'djangosaml2idp.processors.BaseProcessor',
            'local_metadata': sp_metadata_xml,
            'metadata_expiration_dt': extract_validuntil_from_metadata(sp_metadata_xml),
            '_attribute_mapping': 'invalid_json_content',
        })

        assert form.is_valid() is False
        assert 'The provided string could not be parsed with json.' in form.errors['_attribute_mapping'][0]

    @pytest.mark.django_db
    def test_metadata_invalid_nodict(self):
        form = ServiceProviderAdminForm({
            'entity_id': 'entity-id',
            '_processor': 'djangosaml2idp.processors.BaseProcessor',
            'local_metadata': sp_metadata_xml,
            'metadata_expiration_dt': extract_validuntil_from_metadata(sp_metadata_xml),
            '_attribute_mapping': json.dumps(''),
        })

        assert form.is_valid() is False
        assert 'The provided attribute_mapping should be a string representing a dict.' in form.errors['_attribute_mapping'][0]

    @pytest.mark.django_db
    def test_metadata_invalid_dict_wroncontent(self):
        form = ServiceProviderAdminForm({
            'entity_id': 'entity-id',
            '_processor': 'djangosaml2idp.processors.BaseProcessor',
            'local_metadata': sp_metadata_xml,
            'metadata_expiration_dt': extract_validuntil_from_metadata(sp_metadata_xml),
            '_attribute_mapping': json.dumps({
                1: 2,
            }),
        })

        assert form.is_valid() is False
        assert 'The provided attribute_mapping should be a dict with strings for both all keys and values.' in form.errors['_attribute_mapping'][0]
