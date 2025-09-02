from django.conf import settings

MFA_VERIFIED_SESSION_KEY = "mfa-verified"
MFA_VERIFY_INTERNAL_NAME = "mfa-verify"
MFA_SETUP_INTERNAL_NAME = "mfa-setup"


def admin_path():
    return getattr(settings, "ADMIN_PATH", "admin/")


def project_name():
    return getattr(settings, "ADMIN_OTP_PROJECT_NAME", None)


def device_token_cookie_name():
    return getattr(settings, "ADMIN_OTP_DEVICE_TOKEN_COOKIE_NAME", "admin_otp_trusted_device")


def trusted_device_days():
    return getattr(settings, "ADMIN_OTP_TRUSTED_DEVICE_DAYS", 30)


def force_otp():
    return bool(getattr(settings, "ADMIN_OTP_FORCE", 0))


if not settings.TEMPLATES:
    settings.TEMPLATES = [{"OPTIONS": {"context_processors": []}}]

settings.TEMPLATES[0]["OPTIONS"]["context_processors"].append(
    "django_admin_otp.context_processors.admin_otp.settings",
)
