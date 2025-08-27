import base64
import io

import qrcode


def generate_qr_image(uri):
    """Возвращает base64-картинку QR-кода"""
    qr = qrcode.make(uri)
    buf = io.BytesIO()
    qr.save(buf, format="PNG")
    img_b64 = base64.b64encode(buf.getvalue()).decode("utf-8")
    return f"data:image/png;base64,{img_b64}"
