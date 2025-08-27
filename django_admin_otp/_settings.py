from django.conf import settings

DEFAULT_ADMIN_PREFIX = "/admin/"
MFA_VERIFIED_SESSION_KEY = "mfa-verified"
MFA_VERIFY_INTERNAL_NAME = "mfa-verify"
MFA_SETUP_INTERNAL_NAME = "mfa-setup"

PROJECT_NAME = getattr(settings, "ADMIN_OTP_PROJECT_NAME", None)
DEVICE_TOKEN_COOKIE_NAME = getattr(settings, "ADMIN_OTP_DEVICE_TOKEN_COOKIE_NAME", "trusted_device")
ADMIN_PREFIX = getattr(settings, "ADMIN_PATH_PREFIX", DEFAULT_ADMIN_PREFIX)
TRUSTED_DEVICE_DAYS = getattr(settings, "ADMIN_OTP_TRUSTED_DEVICE_DAYS", 30)
FORCE_OTP = getattr(settings, "ADMIN_OTP_FORCE", True)
