from django.urls import include, path
from django.contrib.auth import views as auth_views

from . import views

app_name = 'example_sp'

urlpatterns = [
    path('logout/', auth_views.LogoutView.as_view()),
    path('saml2/', include('djangosaml2.urls')),
    path('', views.IndexView.as_view()),
]
