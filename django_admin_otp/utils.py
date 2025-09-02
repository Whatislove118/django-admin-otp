import base64
import io

import qrcode

from django_admin_otp import settings


def generate_qr_image(uri):
    """Returns base64-image for QR-code"""
    qr = qrcode.make(uri)
    buf = io.BytesIO()
    qr.save(buf, format="PNG")
    img_b64 = base64.b64encode(buf.getvalue()).decode("utf-8")
    return f"data:image/png;base64,{img_b64}"


def admin_url():
    return f"/{settings.ADMIN_PATH}"
