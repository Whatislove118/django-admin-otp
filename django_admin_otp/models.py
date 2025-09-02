from datetime import timedelta

import pyotp
from django.contrib.auth import get_user_model
from django.core import signing
from django.db import models
from django.utils import timezone
from django.utils.crypto import get_random_string

from django_admin_otp import settings


def generate_secret_key_cipher():
    return signing.dumps(pyotp.random_base32())


User = get_user_model()


class OTPVerification(models.Model):
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name="admin_otp_verification",
        verbose_name="user",
    )
    secret_key_cipher = models.CharField(max_length=255, default=generate_secret_key_cipher)
    confirmed = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"OTP Verification for User {self.user_id}"

    @property
    def secret_key(self):
        return signing.loads(self.secret_key_cipher)

    @property
    def totp(self):
        return pyotp.TOTP(self.secret_key)

    def generate_qr_code_uri(self):
        return self.totp.provisioning_uri(
            name=self.user.username,
            issuer_name=settings.PROJECT_NAME,
        )

    def verify(self, code):
        return self.totp.verify(code)


class TrustedDeviceQuerySet(models.QuerySet):
    def active(self):
        return self.filter(expires_at__gt=timezone.now())

    def by_token_cipher(self, token_cipher):
        return self.filter(token=signing.loads(token_cipher))


class TrustedDevice(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="admin_otp_trusted_devices")
    device_info = models.CharField(max_length=255)
    token = models.CharField(max_length=64, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

    objects = TrustedDeviceQuerySet.as_manager()

    def __str__(self):
        return f"OTP Trusted Device for User {self.user_id}"

    @classmethod
    def create_for_user(cls, user, device_info):
        token = get_random_string(64)
        expires_at = timezone.now() + timedelta(days=settings.TRUSTED_DEVICE_DAYS)
        return cls.objects.create(
            user=user,
            token=token,
            device_info=device_info,
            expires_at=expires_at,
        )

    @property
    def token_cipher(self):
        return signing.dumps(self.token)
