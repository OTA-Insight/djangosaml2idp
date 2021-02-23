import pytest
from django.core.exceptions import ImproperlyConfigured
from saml2.server import Server

from djangosaml2idp.idp import IDP
from .settings import SAML_IDP_CONFIG

class TestIDP:
    @pytest.mark.django_db
    def test_idp_load_default_settings_defined_and_valid(self):
        IDP._servers_instaces = {}
        srv = IDP.load()
        assert isinstance(srv, Server)

    @pytest.mark.django_db
    def test_idp_load_no_settings_defined(self, settings):
        IDP._servers_instaces = {}
        settings.SAML_IDP_CONFIG = None
        with pytest.raises(ImproperlyConfigured):
            IDP.load()

    @pytest.mark.django_db
    def test_metadata_no_sp_defined_valid(self):
        IDP._servers_instaces = {}
        md =  IDP.load().get_metadata()
        assert isinstance(md, str)

    @pytest.mark.django_db
    def test_metadata_no_settings_defined(self, settings):
        IDP._servers_instaces = {}
        settings.SAML_IDP_CONFIG = None
        with pytest.raises(ImproperlyConfigured):
             IDP.load().get_metadata()
