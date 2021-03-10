import copy
import pytest
from unittest import mock
from django.core.exceptions import ImproperlyConfigured
from saml2.server import Server

from djangosaml2idp.idp import IDP
from djangosaml2idp.models import ServiceProvider
from .settings import SAML_IDP_CONFIG

def conf_loader(c, r):
    return { "entityid": SAML_IDP_CONFIG["entityid"] }

class TestIDP:
    def teardown_method(self):
        IDP.flush()

    @pytest.mark.django_db
    def test_load_default_settings_defined_and_valid(self):
        srv = IDP.load()
        assert isinstance(srv, Server)

    @pytest.mark.django_db
    def test_load_no_settings_defined(self, settings):
        settings.SAML_IDP_CONFIG = None
        with pytest.raises(ImproperlyConfigured):
            IDP.load()

    @pytest.mark.django_db
    def test_load_cache(self):
        s1 = IDP.load()
        s2 = IDP.load(config_loader_path=conf_loader)
        assert s1 == s2

    @pytest.mark.django_db
    def test_load_constructsp_queryset(self, settings):
        called = False
        def identity_queryset(queryset, request):
            nonlocal called
            called = True
            return queryset

        settings.SAML_IDP_FILTER_SP_QUERYSET = identity_queryset
        IDP.load()
        assert called

    @pytest.mark.django_db
    @mock.patch('saml2.config.IdPConfig.load')
    def test_construct_metadata(self, mock):
        conf = { "a": 1, "b": 2 }
        IDP.construct_metadata(copy.deepcopy(conf))
        mock.assert_called_with({ **conf, "metadata": { "local": [] } })

    @pytest.mark.django_db
    @mock.patch('saml2.config.IdPConfig.load')
    def test_construct_metadata_raise(self, mock):
        mock.side_effect =  ImproperlyConfigured()
        conf = { "a": 1, "b": 2 }
        with pytest.raises(ImproperlyConfigured):
            IDP.construct_metadata(copy.deepcopy(conf))

    @pytest.mark.django_db
    def test_flush(self):
        s1 = IDP.load()
        IDP.flush()
        s2 = IDP.load(config_loader_path=conf_loader)
        assert s1 != s2
    
    @pytest.mark.django_db
    def test_get_metadata_no_sp_defined_valid(self):
        md =  IDP.metadata()
        assert isinstance(md, str)

    @pytest.mark.django_db
    def test_get_metadata_no_idp_in_settings(self, settings):
        # only the first level attribute can be changed to allow the fixture to revert
        idp_config = copy.deepcopy(settings.SAML_IDP_CONFIG)
        del idp_config['service']['idp']
        settings.SAML_IDP_CONFIG = idp_config
        with pytest.raises(ImproperlyConfigured):
             IDP.metadata()
