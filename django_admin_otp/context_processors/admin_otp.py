from django_admin_otp import settings as configuration


def settings(request):  # noqa: ARG001
    return {
        "FORCE_OTP": configuration.FORCE_OTP,
        "TRUSTED_DEVICE_DAYS": configuration.TRUSTED_DEVICE_DAYS,
    }
