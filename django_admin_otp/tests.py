from datetime import timedelta
from unittest import mock
from unittest.mock import patch

from django.contrib import admin
from django.contrib.auth.models import AnonymousUser, User
from django.core import signing
from django.test import Client, RequestFactory, TestCase
from django.urls import reverse
from django.utils import timezone
from django.utils.crypto import get_random_string

from django_admin_otp import settings
from django_admin_otp.admin import MFAForm, TrustedDeviceAdmin
from django_admin_otp.middleware import AdminOTPMiddleware
from django_admin_otp.models import OTPVerification, TrustedDevice
from django_admin_otp.views import mfa_setup, mfa_verify


class AdminOTPMiddlewareTest(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.user = User.objects.create_user(username="testuser", password=get_random_string(16), is_staff=True)
        self.middleware = AdminOTPMiddleware(get_response=lambda _: "OK")
        self.admin_path = f"/{settings.ADMIN_PATH}/some-page/"
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
        request.COOKIES = {settings.DEVICE_TOKEN_COOKIE_NAME: device.token_cipher}

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
        request.COOKIES = {settings.DEVICE_TOKEN_COOKIE_NAME: device.token_cipher}

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


class MFAVerifyViewTest(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.user = User.objects.create_user(username="testuser", password="12345", is_staff=True)
        self.verification = OTPVerification.objects.create(user=self.user, confirmed=True, secret_key_cipher="abc")

    @patch.object(OTPVerification, "verify", return_value=True)
    def test_post_valid_code_trust_device(self, mock_verify):
        request = self.factory.post("/mfa-verify/", data={"code": "123456", "trust_device": True})
        request.user = self.user
        request.session = {}
        request.META["HTTP_USER_AGENT"] = "test-agent"

        response = mfa_verify(request)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, f"/{settings.ADMIN_PATH}")
        self.assertIn(settings.DEVICE_TOKEN_COOKIE_NAME, response.cookies)
        self.assertTrue(request.session.get(settings.MFA_VERIFIED_SESSION_KEY))

    @patch.object(OTPVerification, "verify", return_value=True)
    def test_post_valid_code_no_trust_device(self, mock_verify):
        request = self.factory.post("/mfa-verify/", data={"code": "123456", "trust_device": False})
        request.user = self.user
        request.session = {}
        request.META["HTTP_USER_AGENT"] = "test-agent"

        response = mfa_verify(request)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, f"/{settings.ADMIN_PATH}")
        self.assertNotIn(settings.DEVICE_TOKEN_COOKIE_NAME, response.cookies)
        self.assertTrue(request.session.get(settings.MFA_VERIFIED_SESSION_KEY))

    def test_post_invalid_form(self):
        request = self.factory.post("/mfa-verify/", data={"code": "9999990", "trust_device": True})
        request.user = self.user
        request.session = {}
        request.META["HTTP_USER_AGENT"] = "test-agent"

        response = mfa_verify(request)

        self.assertEqual(response.status_code, 200)
        self.assertIn("Wrong form", response.content.decode())

    def test_post_verify_error(self):
        request = self.factory.post("/mfa-verify/", data={"code": "9999990", "trust_device": True})
        request.user = self.user
        request.session = {}
        request.META["HTTP_USER_AGENT"] = "test-agent"

        with patch.object(OTPVerification, "verify", return_value=False):
            response = mfa_verify(request)

        self.assertEqual(response.status_code, 200)
        self.assertIn("Wrong form", response.content.decode())

    def test_get_request_renders_template(self):
        request = self.factory.get("/mfa-verify/")
        request.user = self.user
        request.session = {}

        response = mfa_verify(request)

        self.assertEqual(response.status_code, 200)


class MFASetupViewTest(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.user = User.objects.create_user(username="setupuser", password="12345", is_staff=True)

    @patch("django_admin_otp.utils.generate_qr_image", return_value="qr_image")
    def test_get_renders_qr(self, mock_qr):
        request = self.factory.get("/mfa-setup/")
        request.user = self.user
        request.session = {}

        response = mfa_setup(request)

        self.assertEqual(response.status_code, 200)
        self.assertIn("qr_image", response.content.decode())

    @patch.object(OTPVerification, "verify", return_value=True)
    @patch("django_admin_otp.views.utils.generate_qr_image", return_value="qr_image")
    def test_post_valid_code_confirms_otp(self, mock_qr, mock_verify):
        verification = OTPVerification.objects.create(user=self.user)
        request = self.factory.post("/mfa-setup/", data={"code": "123456"})
        request.user = self.user
        request.session = {}

        response = mfa_setup(request)
        verification.refresh_from_db()

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, f"/{settings.ADMIN_PATH}")
        self.assertTrue(verification.confirmed)

    @patch.object(OTPVerification, "verify", return_value=False)
    @patch("django_admin_otp.views.utils.generate_qr_image", return_value="qr_image")
    def test_post_invalid_code_renders_template_wrong_form(self, mock_qr, mock_verify):
        OTPVerification.objects.create(user=self.user)
        request = self.factory.post("/mfa-setup/", data={"code": "9999990"})
        request.user = self.user
        request.session = {}

        response = mfa_setup(request)

        self.assertEqual(response.status_code, 200)
        self.assertIn("Wrong form data", response.content.decode())

    @patch.object(OTPVerification, "verify", return_value=False)
    @patch("django_admin_otp.views.utils.generate_qr_image", return_value="qr_image")
    def test_post_invalid_code_renders_template_invalid_code(self, mock_qr, mock_verify):
        verification = OTPVerification.objects.create(user=self.user)
        verification.verify = mock.Mock(return_value=False)
        request = self.factory.post("/mfa-setup/", data={"code": "999999"})
        request.user = self.user
        request.session = {}

        response = mfa_setup(request)

        self.assertEqual(response.status_code, 200)
        self.assertIn("Wrong code", response.content.decode())


class OTPVerificationAdminTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_superuser(username="admin", password="12345", email="admin@test.com")
        self.client.login(username="admin", password="12345")
        self.verification = OTPVerification.objects.create(
            user=self.user,
            confirmed=False,
            secret_key_cipher=signing.dumps("abc"),
        )
        settings.FORCE_OTP = False

    @patch("django_admin_otp.utils.generate_qr_image", return_value="qr_image")
    def test_setup_mfa_get_renders_template(self, mock_qr):
        url = reverse("admin:setup-mfa")

        response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "qr_image")
        self.assertIsInstance(response.context["form"], MFAForm)

    @patch.object(OTPVerification, "verify", return_value=True)
    def test_setup_mfa_post_valid_code_confirms(self, mock_verify):
        url = reverse("admin:setup-mfa")

        response = self.client.post(url, data={"code": "123456"})
        self.verification.refresh_from_db()

        self.assertEqual(response.status_code, 302)
        self.assertTrue(self.verification.confirmed)
        self.assertFalse(response.wsgi_request.user.is_authenticated)  # logout after successful setup mfa

    @patch.object(OTPVerification, "verify", return_value=False)
    def test_setup_mfa_post_invalid_code_shows_error(self, mock_verify):
        url = reverse("admin:setup-mfa")

        response = self.client.post(url, data={"code": "wrong"})

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Wrong code")

    @patch.object(OTPVerification, "verify", return_value=True)
    def test_disable_mfa_post_valid_code_deletes_verification(self, mock_verify):
        self.verification.confirmed = True
        self.verification.save()
        TrustedDevice.create_for_user(self.user, device_info="test")
        session = self.client.session
        session[settings.MFA_VERIFIED_SESSION_KEY] = True
        session.save()
        url = reverse("admin:disable-mfa")

        response = self.client.post(url, data={"code": "123456"})

        self.assertEqual(response.status_code, 302)
        self.assertFalse(OTPVerification.objects.filter(user=self.user).exists())
        self.assertFalse(TrustedDevice.objects.filter(user=self.user).exists())
        self.assertFalse(response.wsgi_request.user.is_authenticated)
        self.assertTrue(settings.DEVICE_TOKEN_COOKIE_NAME in response.cookies)

    @patch.object(OTPVerification, "verify", return_value=False)
    def test_disable_mfa_post_invalid_code_shows_error(self, mock_verify):
        self.verification.confirmed = True
        self.verification.save()
        session = self.client.session
        session[settings.MFA_VERIFIED_SESSION_KEY] = True
        session.save()
        url = reverse("admin:disable-mfa")

        response = self.client.post(url, data={"code": "wrong"})

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Wrong code")


class TrustedDeviceAdminTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_superuser(username="admin", password="12345", email="admin@test.com")
        self.client.login(username="admin", password="12345")
        self.device = TrustedDevice.create_for_user(user=self.user, device_info="test-device")

    def test_change_permission_for_owner(self):
        admin_instance = TrustedDeviceAdmin(TrustedDevice, admin.site)

        self.assertTrue(
            admin_instance.has_change_permission(request=self.client.request().wsgi_request, obj=self.device),
        )

    def test_change_permission_for_other_user(self):
        other_user = User.objects.create_user(username="other", password="12345")
        self.device.user = other_user
        self.device.save()

        admin_instance = TrustedDeviceAdmin(TrustedDevice, admin.site)

        self.assertFalse(
            admin_instance.has_change_permission(request=self.client.request().wsgi_request, obj=self.device),
        )

    def test_delete_permission_for_owner(self):
        admin_instance = TrustedDeviceAdmin(TrustedDevice, admin.site)

        self.assertTrue(
            admin_instance.has_delete_permission(request=self.client.request().wsgi_request, obj=self.device),
        )

    def test_delete_permission_for_other_user(self):
        other_user = User.objects.create_user(username="other", password="12345")
        self.device.user = other_user
        self.device.save()

        admin_instance = TrustedDeviceAdmin(TrustedDevice, admin.site)

        self.assertFalse(
            admin_instance.has_delete_permission(request=self.client.request().wsgi_request, obj=self.device),
        )
