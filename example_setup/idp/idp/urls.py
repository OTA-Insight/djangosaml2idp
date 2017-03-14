from django.conf.urls import url, include
from django.contrib import admin
from django.contrib.auth.views import login

import djangosaml2idp

urlpatterns = [
    #url(r'^idp/', include('djangosaml2idp.urls')),
    url(r'^idp/', include('djangosaml2idp.urls')),
    url(r'^admin/', admin.site.urls),
    url(r'^login/$', login, {'template_name': 'idp/login.html'}, name='login'),
]
