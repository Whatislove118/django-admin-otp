from django.urls import path

from django_admin_otp import settings
from .views import mfa_setup, mfa_verify

urlpatterns = [
    path("verify/", mfa_verify, name=settings.MFA_VERIFY_INTERNAL_NAME),
    path("setup/", mfa_setup, name=settings.MFA_SETUP_INTERNAL_NAME),
]
