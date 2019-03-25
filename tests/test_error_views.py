from django.http import HttpRequest

from djangosaml2idp.error_views import SamlIDPErrorView


view = SamlIDPErrorView.as_view()


class TestErrorView:
    def test_uses_correct_template(self, client):
        request = HttpRequest()
        request.method = 'GET'
        response = view(request)
        assert response.status_code == 200
