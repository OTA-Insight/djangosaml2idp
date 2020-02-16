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
    def test_metadata_no_settings_defined(self, settings):
        IDP._server_instance = None
        settings.SAML_IDP_CONFIG = None
        with pytest.raises(ImproperlyConfigured):
            IDP.metadata()
