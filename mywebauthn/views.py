import logging
from cyberdemo import settings
from django.contrib import auth
from django.contrib import messages
from django.contrib.admin.views.decorators import staff_member_required
from django.http import HttpResponse, HttpResponseRedirect, HttpResponseForbidden
from django.shortcuts import reverse, render
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.utils.translation import gettext_lazy as _
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import FormView, TemplateView
from fido2 import cbor
from fido2.client import ClientData
from fido2.ctap2 import AttestationObject, AuthenticatorData
from fido2.server import Fido2Server
from fido2.utils import websafe_encode, websafe_decode
from fido2.webauthn import PublicKeyCredentialRpEntity
from .forms import *
from .models import *


def get_fido2_conf(name, default=''):
    """
    Lookup `name` in settings.FIDO2 dict or settings.FIDO2_{NAME},
        default to `default` otherwise.
    """
    if hasattr(settings, 'FIDO2'):
        return settings.FIDO2.get(name, default)

    key = f'FIDO2_{name.upper()}'
    if hasattr(settings, key):
        return getattr(settings, key)

    return default


def get_cbor_resp(data=None, redirect=None):
    resp = HttpResponse(content_type="application/cbor")
    if data:
        resp.write(cbor.encode(data))
    if redirect:
        resp.write(redirect)
    return resp


logger = logging.getLogger(__name__)
RP = PublicKeyCredentialRpEntity(get_fido2_conf('rp_url'), get_fido2_conf('rp_name'))
SERVER = Fido2Server(RP)
STATUS_OK = get_cbor_resp({"status": "OK"})
FIDO2_STATE_KEY = get_fido2_conf('session_state_key', 'FIDO2_STATE')
FIDO2_USER_KEY = get_fido2_conf('session_user_key', 'FIDO2_USER')


def get_fido2_credentials(user):
    if user:
        return [ x.credential for x in user.authenticators.all() ]
    return None

def get_fido2_state(req):
    return req.session.get(FIDO2_STATE_KEY, None)


def logreq(name, req, level='warn'):
    getattr(logger, level)(f'{name}() inbound request {req.method.lower()}: {getattr(req, req.method)}.')


def fido2_register_begin(req):
    user = None
    logreq('fido2_register_begin', req)
    token = req.POST.get('username', None)
    if token:
        try:
            t = Token.objects.get(pk=token)
            user = t.redeem()
        except Exception as e:
            messages.error(req, f'Bad registration token.')
            logger.error(f'Token "{token}" lookup and redemtion failed: {e}')
    if user:
        logger.debug(f'User "{user}" redeemed token "{token}".')
        auth.login(req, user)
        data, state = SERVER.register_begin(
            user=get_user_dict(user),
            credentials=get_fido2_credentials(user),
            user_verification=get_fido2_conf('user_verification', 'discouraged'),
            authenticator_attachment=get_fido2_conf('authenticator_attachment', 'cross-platform'))
        logger.info(f'register_begin creds for user "{user.username}": {data}')
        req.session[FIDO2_STATE_KEY] = state
        req.session[FIDO2_USER_KEY] = user.username
        return get_cbor_resp(data)
    elif t and not t.valid():
        messages.error(req, 'Registration token is no longer valid. Please request a new one.')
    return HttpResponseForbidden()

@csrf_exempt
def fido2_register_complete(req):
    user = None
    logreq('fido2_register_complete', req)
    username = req.session.get(FIDO2_USER_KEY, None)
    if username:
        user = get_user_model().objects.get(username=username)
        logger.debug(f'Loaded user "{user.username}"...')
    if user:
        data = cbor.decode(req.body)
        cdat = ClientData(data['clientDataJSON'])
        atto = AttestationObject(data['attestationObject'])
        stat = req.session.get(FIDO2_STATE_KEY, None)
        adat = SERVER.register_complete(stat, cdat, atto)
        cred = adat.credential_data
        adev = user.authenticators.create(user=user, credential=adat.credential_data)
        logger.info(f'register_complete creds for user "{user.username}": {adat.credential_data.credential_id}')
        auth.login(req, user)
        return get_cbor_resp(redirect='/')
    return HttpResponseForbidden()


def fido2_login_begin(req):
    user = None
    logreq('fido2_login_begin', req)
    username = req.POST.get('username', None)
    if username:
        try:
            user = get_user_model().objects.get(username=username)
        except Exception as e:
            messages.error(req, f'Cannot login as that user.')
            logger.error(f'User "{user}" lookup failed: {e}')
    if user:
        creds = get_fido2_credentials(user)
        data, state = SERVER.authenticate_begin(creds)
        req.session[FIDO2_STATE_KEY] = state
        req.session[FIDO2_USER_KEY] = username
        logger.debug(f'login_begin for user "{user.username}": {data}')
        return get_cbor_resp(data)
    return HttpResponseForbidden()

@csrf_exempt
def fido2_login_complete(req):
    user = None
    logreq('fido2_login_complete', req)
    username = req.session.get(FIDO2_USER_KEY, None)
    if username:
        user = get_user_model().objects.get(username=username)
    if user:
        creds = get_fido2_credentials(user)
        data = cbor.decode(req.body)
        crid = data['credentialId']
        cdat = ClientData(data['clientDataJSON'])
        adat = AuthenticatorData(data['authenticatorData'])
        csig = data['signature']
        stat = get_fido2_state(req)
        try:
            SERVER.authenticate_complete(stat, creds, crid, cdat, adat, csig)
        except ValueError as e:
            logger.warn('Failed fido2 authentication', e)
            return HttpResponseForbidden()
        found = False
        for a in user.authenticators.all():
            if a.crid == crid:
                a.inc_counter()
                found = True
                break
        if not found:
            logger.warn(f'Failed to bump fido2 counter for cred-id "{crid}" owned by "{user.username}".')
        auth.login(req, user)
        messages.info(req, f'Welcome back {user.get_full_name() or user.username}.')
        logger.info(f'login_complete successful for user "{user.username}".')
        return get_cbor_resp(redirect='/')
    return HttpResponseForbidden()


class LoginView(TemplateView):
    template_name = 'mywebauthn/login.html'

class RegistrationView(TemplateView):
    template_name = 'mywebauthn/register.html'


@method_decorator(staff_member_required, name="dispatch")
class CreateUserView(FormView):
    template_name = 'mywebauthn/create.html'
    form_class    = UserForm

    def get_success_url(self):
        return self.request.path

    def form_valid(self, form):
        user, created = get_user_model().objects.get_or_create(
                            username=form.cleaned_data['username'],
                            email=form.cleaned_data['email'],
                            is_superuser=form.cleaned_data['is_superuser'],
                            is_staff=form.cleaned_data['is_superuser'],
                            is_active=True)
        if not created:
            user.tokens.all().delete()
        user.set_unusable_password()
        user.save()
        token = Token.objects.create(user=user)
        messages.info(self.request, f'Created user "{user.username}" with token "{token.pk}".')
        return super().form_valid(form)
