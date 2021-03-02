from unittest.mock import patch, Mock
import pytest
from django.core.exceptions import ImproperlyConfigured
from saml2.server import Server

from djangosaml2idp.idp import IDP


class TestIDP:

    @pytest.mark.django_db
    def test_idp_load_default_settings_defined_and_valid(self):
        IDP._server_instance = None
        srv = IDP.load()
        assert isinstance(srv, Server)

    @pytest.mark.django_db
    def test_idp_load_no_settings_defined(self, settings):
        IDP._server_instance = None
        settings.SAML_IDP_CONFIG = None
        with pytest.raises(ImproperlyConfigured):
            IDP.load()

    @pytest.mark.django_db
    def test_metadata_no_sp_defined_valid(self):
        IDP._server_instance = None
        md = IDP.metadata()
        assert isinstance(md, str)

    @pytest.mark.django_db
    @patch('djangosaml2idp.models.ServiceProvider')
    def test_metadata_sp_autoload_idp(self, sp_model_mock):
        '''The IdP metadata should not require loading of SP metadata.'''
        sp_instance_mock = Mock()
        sp_instance_mock.metadata_path.return_value = '/tmp/djangosaml2idp/1.xml'
        sp_model_mock.objects.filter.return_value = [sp_instance_mock]
        IDP._server_instance = None
        md = IDP.metadata()
        sp_instance_mock.metadata_path.assert_not_called()


    @pytest.mark.django_db
    def test_metadata_no_settings_defined(self, settings):
        IDP._server_instance = None
        settings.SAML_IDP_CONFIG = None
        with pytest.raises(ImproperlyConfigured):
            IDP.metadata()
