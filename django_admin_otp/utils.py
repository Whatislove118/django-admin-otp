import base64
import io
from functools import cache

import qrcode

from django_admin_otp import settings


def generate_qr_image(uri):
    """Returns base64-image for QR-code"""
    qr = qrcode.make(uri)
    buf = io.BytesIO()
    qr.save(buf, format="PNG")
    img_b64 = base64.b64encode(buf.getvalue()).decode("utf-8")
    return f"data:image/png;base64,{img_b64}"


@cache
def admin_url():
    if settings.APP_PREFIX:
        return f"/{settings.APP_PREFIX}/{settings.DEFAULT_ADMIN_PATH}"
    return f"/{settings.DEFAULT_ADMIN_PATH}"
