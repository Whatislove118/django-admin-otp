from django import forms
from django.contrib import admin, messages
from django.contrib.auth import get_user_model, logout
from django.db.transaction import atomic
from django.shortcuts import redirect, render
from django.urls import path

from django_admin_otp import settings, utils
from .models import OTPVerification, TrustedDevice

User = get_user_model()


class MFAForm(forms.Form):
    code = forms.CharField(
        max_length=6,
        required=True,
        widget=forms.TextInput(
            attrs={
                "maxlength": 6,
                "pattern": "[0-9]*",
                "inputmode": "numeric",
            },
        ),
        label="MFA Code",
    )


@admin.register(OTPVerification)
class OTPVerificationAdmin(admin.ModelAdmin):
    list_display = ("user", "confirmed", "created_at")
    readonly_fields = ("user", "confirmed", "created_at")
    actions = None  # remove standart actions
    fields = (
        "user",
        "confirmed",
        "created_at",
    )
    change_list_template = "admin/otpverification_changelist.html"

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    def get_urls(self):
        urls = super().get_urls()
        custom_urls = [
            path("setup-mfa/", self.admin_site.admin_view(self.setup_mfa), name="setup-mfa"),
            path("disable-mfa/", self.admin_site.admin_view(self.disable_mfa), name="disable-mfa"),
        ]
        return custom_urls + urls

    def qr_preview(self, obj):
        if not obj or obj.confirmed:
            return ""
        uri = obj.generate_qr_code_uri()
        img_data = utils.generate_qr_image(uri)
        return f'<img src="{img_data}" width="200" height="200"/>'

    qr_preview.allow_tags = True
    qr_preview.short_description = "QR Code"

    @atomic
    def setup_mfa(self, request):
        user = request.user
        verification, _ = OTPVerification.objects.get_or_create(user=user)

        if verification.confirmed:
            messages.warning(request, "MFA has been already connected")
            return redirect("..")

        form = MFAForm()
        if request.method == "POST":
            form = MFAForm(request.POST)
            if form.is_valid():
                code = form.cleaned_data["code"]
                if verification.verify(code):
                    verification.confirmed = True
                    verification.save()
                    messages.success(request, "MFA had been connected successfully")
                    logout(request)
                    return redirect("..")

                form.add_error("code", "Wrong code")

        uri = verification.generate_qr_code_uri()
        qr_img = utils.generate_qr_image(uri)
        return render(
            request,
            "admin/mfa_popup.html",
            {
                "form": form,
                "qr_img": qr_img,
                "title": "Connect MFA",
            },
        )

    @atomic
    def disable_mfa(self, request):
        user = request.user
        verification = getattr(user, "admin_otp_verification", None)
        if not verification or not verification.confirmed:
            messages.warning(request, "MFA hasn't been connected")
            return redirect("..")

        form = MFAForm()
        if request.method == "POST":
            form = MFAForm(request.POST)
            if form.is_valid():
                code = form.cleaned_data["code"]
                if verification.verify(code):
                    self._disable_cleanup(request, verification, user)
                    logout(request)
                    messages.success(request, "MFA has been disconnected")
                    response = redirect("..")
                    response.delete_cookie(settings.DEVICE_TOKEN_COOKIE_NAME)
                    return response

                form.add_error("code", "Wrong code")

        return render(request, "admin/mfa_popup.html", {"form": form, "title": "Disable MFA"})

    def _disable_cleanup(self, request, verification, user):
        verification.delete()
        TrustedDevice.objects.filter(user=user).delete()
        if settings.MFA_VERIFIED_SESSION_KEY in request.session:
            del request.session[settings.MFA_VERIFIED_SESSION_KEY]


@admin.register(TrustedDevice)
class TrustedDeviceAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "device_info", "created_at", "expires_at")
    list_filter = ["expires_at", "created_at"]
    search_fields = ["user__username", "user__id", "device_info__icontains"]
    autocomplete_fields = ["user"]
    readonly_fields = ["user"]
    exclude = ["token"]

    def has_change_permission(self, request, obj=None):
        if not obj:
            return False

        return obj.user == request.user

    def has_delete_permission(self, request, obj=None):
        if not obj:
            return False

        return obj.user == request.user
