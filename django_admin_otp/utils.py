import base64
import io

import qrcode

from django_admin_otp import settings
from django_admin_otp.models import TrustedDevice


def generate_qr_image(uri):
    """Returns base64-image for QR-code"""
    qr = qrcode.make(uri)
    buf = io.BytesIO()
    qr.save(buf, format="PNG")
    img_b64 = base64.b64encode(buf.getvalue()).decode("utf-8")
    return f"data:image/png;base64,{img_b64}"


def admin_url():
    return f"/{settings.ADMIN_PATH}"


def is_trusted_device_request(request):
    trusted_token_cipher = request.COOKIES.get(settings.DEVICE_TOKEN_COOKIE_NAME)
    if not trusted_token_cipher:
        return False

    # If user has trusted device cookie and device is exists - no need to check
    return (
        TrustedDevice.objects.filter(user=request.user)
        .by_token_cipher(token_cipher=trusted_token_cipher)
        .active()
        .exists()
    )


def is_request_mfa_verified(request):
    return bool(request.session.get(settings.MFA_VERIFIED_SESSION_KEY, False))
