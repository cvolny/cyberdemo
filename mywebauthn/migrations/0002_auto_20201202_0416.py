# Generated by Django 3.1.4 on 2020-12-02 04:16

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('mywebauthn', '0001_initial'),
    ]

    operations = [
        migrations.RenameField(
            model_name='authenticator',
            old_name='auth_data',
            new_name='cred_data',
        ),
    ]
