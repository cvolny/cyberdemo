from django.contrib import admin
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from .forms import *
from .models import *


class UserAdmin(admin.ModelAdmin):
    fields = ('username', 'email', 'is_staff', 'is_superuser', 'is_active',)

admin.site.unregister(Group)
admin.site.unregister(get_user_model())
admin.site.register(get_user_model(), UserAdmin)


def renew_token(admin, request, queryset):
    for token in queryset.all():
        token.renew()
        token.save()
renew_token.short_description = "Renew expiration and unredeem selected"

class TokenAdmin(admin.ModelAdmin):
    readonly_fields = ('token', 'expires', 'redeemed',)
    actions = (renew_token,)


class AuthAdmin(admin.ModelAdmin):
    readonly_fields = ('counter',)

admin.site.register(Token, TokenAdmin)
admin.site.register(Authenticator, AuthAdmin)
