import os

from django.conf import settings

MFA_VERIFIED_SESSION_KEY = "mfa-verified"
MFA_VERIFY_INTERNAL_NAME = "mfa-verify"
MFA_SETUP_INTERNAL_NAME = "mfa-setup"

PROJECT_NAME = os.environ.get("ADMIN_OTP_PROJECT_NAME", None)
DEVICE_TOKEN_COOKIE_NAME = os.environ.get("ADMIN_OTP_DEVICE_TOKEN_COOKIE_NAME", "admin_otp_trusted_device")
ADMIN_PATH = os.environ.get("ADMIN_PATH", "admin/")
TRUSTED_DEVICE_DAYS = os.environ.get("ADMIN_OTP_TRUSTED_DEVICE_DAYS", 30)
FORCE_OTP = bool(int(os.environ.get("ADMIN_OTP_FORCE", 0)))


def init():
    if not settings.TEMPLATES:
        settings.TEMPLATES = [
            {
                "BACKEND": "django.template.backends.django.DjangoTemplates",
                "DIRS": [],
                "APP_DIRS": True,
                "OPTIONS": {
                    "context_processors": [
                        "django.template.context_processors.request",
                        "django.contrib.auth.context_processors.auth",
                        "django.contrib.messages.context_processors.messages",
                        "django_admin_otp.context_processors.admin_otp.settings",
                    ],
                },
            },
        ]

    settings.TEMPLATES[0]["OPTIONS"]["context_processors"].append(
        "django_admin_otp.context_processors.admin_otp.settings",
    )
