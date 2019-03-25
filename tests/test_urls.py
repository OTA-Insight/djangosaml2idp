from django.urls import reverse

PREFIX = 'djangosaml2idp:'


# We only really need to test one, because if the urls integration works in general, it will work for all specified urls.
def test_init_url():
    path = reverse(PREFIX + "saml_idp_init")
    assert path == "/sso/init/"
