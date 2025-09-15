from django.contrib.auth.views import LogoutView
from django.urls import path

from django_admin_otp import settings, utils
from .views import mfa_setup, mfa_verify

urlpatterns = [
    path("verify/", mfa_verify, name=settings.MFA_VERIFY_INTERNAL_NAME),
    path("setup/", mfa_setup, name=settings.MFA_SETUP_INTERNAL_NAME),
    path("logout/", LogoutView.as_view(next_page=utils.admin_url()), name="admin-otp-logout"),
]
