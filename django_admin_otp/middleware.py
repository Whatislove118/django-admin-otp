from django.shortcuts import redirect
from django.urls import reverse

from django_admin_otp import _settings
from django_admin_otp.models import OTPVerification, TrustedDevice


class AdminOTPMiddleware:
    """Middleware for detecting if MFA is required for a request"""

    def __init__(self, get_response):
        self.get_response = get_response

        self._admin_prefix = _settings.ADMIN_PREFIX

    def _is_verify_needed(self, request):
        # MFA is only checked for the admin site and authenticated users
        if not (request.path.startswith(self._admin_prefix) and request.user.is_authenticated):
            return False

        # If MFA is already verified in the session → no need to check
        if request.session.get(_settings.MFA_VERIFIED_SESSION_KEY):
            return False

        # If user has trusted device cookie and device is exists - no need to check
        trusted_token = request.COOKIES.get("trusted_device")
        return not (TrustedDevice.objects.filter(user=request.user, device_token=trusted_token).active().exists())

    def __call__(self, request):
        if not self._is_verify_needed(request):
            return self.get_response(request)

        if OTPVerification.objects.filter(user=request.user, confirmed=True).exists():
            if _settings.FORCE_OTP:
                return redirect(_settings.MFA_SETUP_INTERNAL_NAME)
            return self.get_response(request)

        # Ignore MFA check path to avoid redirect loops
        if request.path != reverse(_settings.MFA_VERIFY_INTERNAL_NAME):
            return redirect(_settings.MFA_VERIFY_INTERNAL_NAME)

        return self.get_response(request)
