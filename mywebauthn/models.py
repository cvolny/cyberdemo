from cyberdemo import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from fido2.utils import websafe_encode, websafe_decode
from fido2.ctap2 import AttestedCredentialData
from hashlib import md5


DEFAULT_EXPIRY = 600


def get_user_dict(user):
    return dict(
        id=user.username.encode('utf-8'),
        name=user.username,
        displayName=(user.get_full_name() or user.username)
    )


def get_expiry():
    if hasattr(settings, 'USER_TOKEN_EXPIRY') and settings.USER_TOKEN_EXPIRY:
        return settings.USER_TOKEN_EXPIRY
    return DEFAULT_EXPIRY


class Authenticator(models.Model):
    user      = models.ForeignKey(get_user_model(), related_name="authenticators", on_delete=models.CASCADE)
    created   = models.DateTimeField(_('Created'), auto_now_add=True)
    cred_id   = models.TextField(unique=True)
    cred_data = models.TextField()
    counter   = models.PositiveIntegerField(default=1)

    def inc_counter(self):
        self.counter += 1
        self.save()
        return self

    @property
    def crid(self):
        return websafe_decode(self.cred_id)

    @property
    def credential(self):
        return AttestedCredentialData(websafe_decode(self.cred_data))

    @credential.setter
    def credential(self, cred):
        self.cred_data = websafe_encode(cred)
        self.cred_id = websafe_encode(cred.credential_id)

    def __str__(self):
        return f'{self.user.username}: {md5(self.crid).hexdigest()} ({self.counter})'


class Token(models.Model):
    token    = models.CharField(_('Token'), max_length=64, primary_key=True)
    user     = models.ForeignKey(get_user_model(), related_name='tokens', on_delete=models.CASCADE, verbose_name=_('User'))
    created  = models.DateTimeField(_('Created'), auto_now_add=True)
    expires  = models.DateTimeField(_('Expires'))
    redeemed = models.DateTimeField(_('Redeemed'), null=True)

    class Meta:
        verbose_name = _('Token')
        verbose_name_plural = _('Tokens')

    def valid(self):
        return self.redeemed == None \
            and not self.expired()

    def expired(self):
        return timezone.now() > self.expires

    def redeem(self):
        if self.valid():
            self.redeemed = timezone.now()
            self.save()
            return self.user
        return False

    def generate_token(self):
        return default_token_generator.make_token(self.user)

    def renew(self):
        self.expires = timezone.now() + timezone.timedelta(minutes=get_expiry())
        self.redeemed = None

    def save(self, *args, **kwargs):
        if not self.expires:
            self.renew()
        if not self.token:
            self.token = self.generate_token()
        return super(Token, self).save(*args, **kwargs)

    def __str__(self):
        return f'{self.user.username}: {self.pk}'
