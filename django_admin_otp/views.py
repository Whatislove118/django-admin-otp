from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render

from django_admin_otp import _settings, utils
from django_admin_otp.forms import OTPForm
from django_admin_otp.models import OTPVerification


@login_required
def mfa_verify(request):
    if request.method != "POST":
        return render(request, "mfa_verify.html")

    user = request.user
    form = OTPForm(request.POST)
    if not form.is_valid():
        return render(request, "mfa_verify.html", {"error": form.errors})

    verification = OTPVerification.objects.only("secret_key_hash").get(user=user, confirmed=True)
    if verification.verify(form.cleaned_data["code"]):
        request.session[_settings.MFA_VERIFIED_SESSION_KEY] = True
        return redirect(_settings.ADMIN_PREFIX)

    return render(request, "mfa_verify.html", {"error": "Wrong code"})


@login_required
def mfa_setup(request):
    verification, _ = OTPVerification.objects.get_or_create(user=request.user)
    if request.method != "POST":
        return render(
            request,
            "mfa_setup.html",
            {"qr_code_url": utils.generate_qr_image(verification.generate_qr_code_uri())},
        )

    form = OTPForm(request.POST)
    if not form.is_valid():
        return render(request, "mfa_setup.html", {"error": "Wrong form data"})

    if verification.verify(form.cleaned_data["code"]):
        verification.confirmed = True
        verification.save()
        return redirect(_settings.ADMIN_PREFIX)

    return render(
        request,
        "mfa_setup.html",
        {
            "qr_code_url": utils.generate_qr_image(verification.generate_qr_code_uri()),
            "error": "Wrong code",
        },
    )
