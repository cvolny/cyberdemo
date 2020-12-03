from django.contrib.auth.views import LogoutView
from django.urls import path
from .views import *


urlpatterns = [
    path('login',    LoginView.as_view(),        name='login'),
    path('register', RegistrationView.as_view(), name='register'),
    path('logout',   LogoutView.as_view(),       name='logout'),
    path('create',   CreateUserView.as_view(),   name='create_user'),

    path('api/register/begin',    fido2_register_begin,       name='fido2_register_begin'),
    path('api/register/complete', fido2_register_complete,    name='fido2_register_complete'),
    path('api/login/begin',       fido2_login_begin,          name='fido2_login_begin'),
    path('api/login/complete',    fido2_login_complete,       name='fido2_login_complete'),
]
