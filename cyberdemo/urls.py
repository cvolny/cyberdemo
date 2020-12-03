from django.contrib import admin
from django.urls import path, include
from django.views.generic import TemplateView
from django.views.generic.base import RedirectView


urlpatterns = [
    path("", TemplateView.as_view(template_name='index.html'), name='index'),
    path('admin/login/', RedirectView.as_view(pattern_name='login')),
    path('admin/logout/', RedirectView.as_view(pattern_name='logout')),
    path('admin/', admin.site.urls),
    path('user/', include('mywebauthn.urls')),
]
