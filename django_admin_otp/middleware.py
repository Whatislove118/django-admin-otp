from django.shortcuts import redirect
from django.urls import reverse

from django_admin_otp import settings
from django_admin_otp.models import OTPVerification, TrustedDevice


class AdminOTPMiddleware:
    """Middleware for detecting if MFA is required for a request"""

    def __init__(self, get_response):
        self.get_response = get_response

        self._admin_prefix = settings.ADMIN_PREFIX

    def _is_verify_needed(self, request):
        # MFA is only checked for the admin site and authenticated users
        if not (request.path.startswith(self._admin_prefix) and request.user.is_authenticated):
            return False

        # If MFA is already verified in the session → no need to check
        if request.session.get(settings.MFA_VERIFIED_SESSION_KEY):
            return False

        trusted_token_cipher = request.COOKIES.get("trusted_device")
        if not trusted_token_cipher:
            return True

        # If user has trusted device cookie and device is exists - no need to check
        return not (
            TrustedDevice.objects.filter(user=request.user)
            .by_token_cipher(token_cipher=trusted_token_cipher)
            .active()
            .exists()
        )

    def __call__(self, request):
        if not self._is_verify_needed(request):
            return self.get_response(request)

        if not OTPVerification.objects.filter(user=request.user, confirmed=True).exists():
            if settings.FORCE_OTP:
                return redirect(settings.MFA_SETUP_INTERNAL_NAME)
            return self.get_response(request)

        # Ignore MFA check path to avoid redirect loops
        if request.path != reverse(settings.MFA_VERIFY_INTERNAL_NAME):
            return redirect(settings.MFA_VERIFY_INTERNAL_NAME)

        return self.get_response(request)
