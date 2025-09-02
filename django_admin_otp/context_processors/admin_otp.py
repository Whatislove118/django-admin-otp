from django_admin_otp import settings as configuration


def settings(request):  # noqa: ARG001
    return {
        "FORCE_OTP": configuration.force_otp(),
        "TRUSTED_DEVICE_DAYS": configuration.trusted_device_days(),
    }
