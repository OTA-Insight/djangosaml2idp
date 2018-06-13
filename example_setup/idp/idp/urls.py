from django.urls import include, path
from django.contrib import admin
from django.contrib.auth.views import login
from django.conf import settings
from django.conf.urls.static import static

import djangosaml2idp

app_name = 'example_idp'
urlpatterns = [
    #path('idp/', include('djangosaml2idp.urls')),
    path('idp/', include('djangosaml2idp.urls', namespace='djangosaml2')),
    path('login/', login, {'template_name': 'idp/login.html'}, name='login'),
    path('admin/', admin.site.urls),
] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
