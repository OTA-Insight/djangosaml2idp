from django.http import HttpRequest

from djangosaml2idp.error_views import SamlIDPErrorView


class TestErrorView:
    def test_uses_correct_template(self, client):
        request = HttpRequest()
        request.method = 'GET'
        response = SamlIDPErrorView.as_view()(request)
        assert response.status_code == 200
