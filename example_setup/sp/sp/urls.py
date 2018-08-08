from django.urls import include, path
from django.contrib import admin
from django.contrib.auth import views as auth_views

from . import views

urlpatterns = [
    path('', views.index),
    path('logout/', auth_views.LogoutView.as_view()),
    path('saml2/', include('djangosaml2.urls')),
]
