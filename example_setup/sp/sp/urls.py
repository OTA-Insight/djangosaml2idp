from django.conf.urls import include, url
from django.contrib import admin
from django.contrib.auth.views import logout

from . import views

urlpatterns = [
    path('', views.index),
    path('logout/', logout),
    path('saml2/', include('djangosaml2.urls')),
]
