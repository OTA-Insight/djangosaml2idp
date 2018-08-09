from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.contrib.auth import views as auth_views
from django.urls import include, path

app_name = 'example_idp'

urlpatterns = [
    #path('idp/', include('djangosaml2idp.urls')),
    path('idp/', include('djangosaml2idp.urls', namespace='djangosaml2')),
    path('login/', auth_views.LoginView.as_view(template_name='idp/login.html'), name='login'),
    path('admin/', admin.site.urls),
] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
