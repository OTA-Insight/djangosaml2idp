from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.contrib.auth import views as auth_views
from django.urls import include, path
from . import views

app_name = 'example_idp'

urlpatterns = [
    path('idp/', include('djangosaml2idp.urls', namespace='djangosaml2')),
    path('login/', auth_views.LoginView.as_view(template_name='idp/login.html'), name='login'),
    path('logout/', auth_views.LogoutView.as_view()),
    path('admin/', admin.site.urls),
    path('', views.IndexView.as_view()),
] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
