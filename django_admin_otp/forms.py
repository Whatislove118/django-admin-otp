from django import forms
from django.conf import settings

class OTPForm(forms.Form):
    code = forms.IntegerField(max_value=999999)
    trust_device = forms.BooleanField(required=False, initial=False)