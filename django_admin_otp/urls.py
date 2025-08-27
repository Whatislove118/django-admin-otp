from django.urls import path

from django_admin_otp import _settings
from .views import mfa_verify, mfa_setup

urlpatterns = [
    path('verify/', mfa_verify, name=_settings.MFA_VERIFY_INTERNAL_NAME),
    path('setup/', mfa_setup, name=_settings.MFA_SETUP_INTERNAL_NAME),
]
