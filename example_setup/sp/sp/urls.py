from django.conf.urls import include, url
from django.contrib import admin
from django.contrib.auth.views import logout

from . import views

urlpatterns = [
    url(r'^$', views.index),
    url(r'^logout/$', logout),
    url(r'^saml2/', include('djangosaml2.urls')),
    url(r'^admin/', admin.site.urls),
]
