from django.urls import include, path
from django.contrib import admin
from django.contrib.auth.views import login

import djangosaml2idp

urlpatterns = [
    #path('idp/', include('djangosaml2idp.urls')),
    path('idp/', include('djangosaml2idp.urls')),
    path('login/', login, {'template_name': 'idp/login.html'}, name='login'),
]
