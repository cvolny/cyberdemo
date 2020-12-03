from django.contrib.auth import get_user_model
from django import forms


class UserForm(forms.ModelForm):
    class Meta:
        model = get_user_model()
        fields = ('username', 'email', 'is_superuser', 'is_active')
