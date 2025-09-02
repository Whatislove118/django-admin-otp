# django-admin-otp

Lightweight **MFA (TOTP) for Django Admin**: enable/disable MFA directly from the admin, verify codes on login, and support "trusted devices" via secure cookies.

---

## Features

- 🔑 TOTP-based MFA for Django Admin (Google Authenticator, Authy, etc.)
- 🛠 Setup MFA from the admin panel (QR code + code entry)
- ❌ Disable MFA with code confirmation
- 💻 Trusted devices: skip MFA for up to N days
- ⚙️ Middleware-based enforcement for admin access
- 📦 Configurable via environment variables
- 🎨 Ready-to-use templates for verification and setup pages

---

## Installation
```bash
pip install django-admin-otp
```
---

## Quickstart
Add this code to settings.py
```python
from django_admin_otp.settings import
# settings.py
INSTALLED_APPS = [
    # ...
    "django.contrib.admin",
    "django_admin_otp",
]
# Should be last middleware
MIDDLEWARE = [
    # ...
    "django_admin_otp.middleware.AdminOTPMiddleware",
]
```
Add urls
```python
from django.contrib import admin
from django.urls import include, path
from django.conf import settings

urlpatterns = [
    path("admin/", admin.site.urls),
    path("admin-mfa/", include("django_admin_otp.urls")),
]

```
Export variables
```
export ADMIN_OTP_PROJECT_NAME "Your-project-name"
```
Run migrations and createsuperuser (if it hasn't created yet):
```bash
python manage.py migrate django_admin_otp
&
python manage.py createsuperuser
```
Run server
```bash
python manage.py runserver
```

---
### How to setup OTP
Go to localhost:8000/admin/, login to panel and go to OTP Verifications panel
![Setup MFA First Step](docs/images/setup_first_step.jpg)
Click on 'Setup MFA for current user'
![Setup MFA Second Step](docs/images/setup_second_step.jpg)
Scan QR and enter code from your app here. Click on submit.
![Setup MFA Third Step](docs/images/setup_third_step.jpg)
If code is correct - MFA for your user would be set. You will be redirected to Django Auth Form (via logout).
Now you can start login process.

---

### OTP Login process
Login into admin panel. After success - you will see theese form.
![Login First Step](docs/images/login_first_step.jpg)
Enter code to from your app and choose trust device option.
If would set - you can login from this device without MFA process. (stored in cookie).
It would worked for some time (see Configuration section).

---

### How to disable
Go to OTPVerification admin panel.
![Disconnect MFA First Step](docs/images/setup_first_step.jpg)
If you have already connected to MFA - the button would be "Disable MFA for Current user"
![Disconnect MFA Second Step](docs/images/disconnect_second_step.jpg)
Click on it, enter code from your app and your mfa (with trusted devices) would be deleted.
![Disconnect MFA Third Step](docs/images/disconnect_third_step.jpg)


---

### Configuration

Configurable environment variables:

- `ADMIN_OTP_PROJECT_NAME` - project name which would display in Auth APP.
- `ADMIN_PATH` — admin URL prefix (default `"admin"`).
- `ADMIN_OTP_FORCE` (int) — require MFA setup for all admin users (default `0`). See `Force OTP` section for more details.
- `ADMIN_OTP_TRUSTED_DEVICE_DAYS` — validity period for trusted devices (defaults `30` days)
- `ADMIN_OTP_DEVICE_TOKEN_COOKIE_NAME` — name of trusted device cookie (default `"admin_otp_trusted_device"`).

---

### FORCE OTP
This parameter change default setup mfa behavior. If is set, all users that tries to login into admin panel would be redirected to setup mfa process. Without set mfa - you wouldn't be able to login in admin panel.
How it goes:
After login you'll see this form
![Force OTP First Step](docs/images/force_otp_first_step.jpg)
After setup mfa - you will be redirected on login to OTP process form
![Login First Step](docs/images/login_first_step.jpg)

---

### How to contribute
...

---

### How to develop

---

### How to test
...
