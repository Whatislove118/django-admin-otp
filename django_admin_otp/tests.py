from datetime import timedelta

from django.contrib.auth.models import AnonymousUser, User
from django.core import signing
from django.test import RequestFactory, TestCase
from django.urls import reverse
from django.utils import timezone
from django.utils.crypto import get_random_string

from django_admin_otp import settings
from django_admin_otp.middleware import AdminOTPMiddleware
from django_admin_otp.models import OTPVerification, TrustedDevice


class AdminOTPMiddlewareTest(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.user = User.objects.create_user(username="testuser", password=get_random_string(16), is_staff=True)
        self.middleware = AdminOTPMiddleware(get_response=lambda _: "OK")
        self.admin_path = settings.ADMIN_PREFIX + "/some-page/"
        self.verify_url = reverse(settings.MFA_VERIFY_INTERNAL_NAME)
        self.setup_url = reverse(settings.MFA_SETUP_INTERNAL_NAME)

    def test_unauthenticated_user_passes(self):
        request = self.factory.get(self.admin_path)
        request.user = AnonymousUser()

        response = self.middleware(request)

        self.assertEqual(response, "OK")

    def test_verified_in_session_passes(self):
        request = self.factory.get(self.admin_path)
        request.user = self.user
        request.session = {settings.MFA_VERIFIED_SESSION_KEY: True}

        response = self.middleware(request)

        self.assertEqual(response, "OK")

    def test_verified_in_session_no_trusted_device_no_force_otp(self):
        request = self.factory.get(self.admin_path)
        request.user = self.user
        request.session = {}
        request.COOKIES = {}

        response = self.middleware(request)

        self.assertEqual(response, "OK")

    def test_requires_mfa_redirects_to_verify(self):
        request = self.factory.get(self.admin_path)
        OTPVerification.objects.create(user=self.user, confirmed=True, secret_key_cipher=signing.dumps("abc"))
        request.user = self.user
        request.session = {}
        request.COOKIES = {}

        response = self.middleware(request)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, self.verify_url)

    def test_trusted_device_allows_access(self):
        OTPVerification.objects.create(user=self.user, confirmed=True, secret_key_cipher=signing.dumps("abc"))
        device = TrustedDevice.create_for_user(user=self.user, device_info="test-agent")
        request = self.factory.get(self.admin_path)
        request.user = self.user
        request.session = {}
        request.COOKIES = {"trusted_device": device.token_cipher}

        response = self.middleware(request)

        self.assertEqual(response, "OK")

    def test_force_otp_redirects_to_setup(self):
        old_value = settings.FORCE_OTP
        settings.FORCE_OTP = True
        try:
            request = self.factory.get(self.admin_path)
            request.user = self.user
            request.session = {}
            request.COOKIES = {}

            response = self.middleware(request)

            self.assertEqual(response.status_code, 302)
            self.assertEqual(response.url, self.setup_url)
        finally:
            settings.FORCE_OTP = old_value

    def test_access_to_mfa_verify_page_does_not_redirect(self):
        OTPVerification.objects.create(user=self.user, confirmed=True, secret_key_cipher=signing.dumps("abc"))
        request = self.factory.get(self.verify_url)
        request.user = self.user
        request.session = {}
        request.COOKIES = {}

        response = self.middleware(request)

        self.assertEqual(response, "OK")

    def test_trusted_device_inactive_requires_mfa(self):
        OTPVerification.objects.create(user=self.user, confirmed=True, secret_key_cipher=signing.dumps("abc"))
        device = TrustedDevice.create_for_user(
            user=self.user,
            device_info="test-agent",
        )
        device.expires_at = timezone.now() - timedelta(days=1)
        device.save()

        request = self.factory.get(self.admin_path)
        request.user = self.user
        request.session = {}
        request.COOKIES = {"trusted_device": device.token_cipher}

        response = self.middleware(request)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, self.verify_url)

    def test_request_outside_admin_prefix_passes(self):
        OTPVerification.objects.create(user=self.user, confirmed=True, secret_key_cipher=signing.dumps("abc"))
        path = "/some-other-page/"
        request = self.factory.get(path)
        request.user = self.user
        request.session = {}
        request.COOKIES = {}

        response = self.middleware(request)

        self.assertEqual(response, "OK")

    def test_no_otp_force_otp_false_passes(self):
        old_value = settings.FORCE_OTP
        settings.FORCE_OTP = False
        try:
            request = self.factory.get(self.admin_path)
            request.user = self.user
            request.session = {}
            request.COOKIES = {}

            response = self.middleware(request)

            self.assertEqual(response, "OK")
        finally:
            settings.FORCE_OTP = old_value
