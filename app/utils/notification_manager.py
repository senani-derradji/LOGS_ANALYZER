import requests
from app.core.config import settings


# -----------------------------
# Check config
# -----------------------------
if not settings.EMAILTOKEN:
    raise Exception("ERROR: EMAILTOKEN missing")

if not settings.NAMEMAIL:
    raise Exception("ERROR: NAMEMAIL missing")


# -----------------------------
# HTML Email Builder
# -----------------------------
def build_verification_email(name: str, verify_link: str):
    return f"""
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Verify Your Email</title>
</head>

<body style="margin:0; padding:0; font-family:Arial, sans-serif; background-color:#f4f6f8;">

  <div style="max-width:600px; margin:40px auto; background:#ffffff; border-radius:10px; overflow:hidden; box-shadow:0 4px 20px rgba(0,0,0,0.08);">

    <!-- Header -->
    <div style="background:#111827; padding:20px; text-align:center;">
      <h2 style="color:#ffffff; margin:0;">Verify Your Email</h2>
    </div>

    <!-- Body -->
    <div style="padding:30px; color:#333;">

      <h3 style="margin-top:0;">Hello {name},</h3>

      <p style="font-size:15px; line-height:1.6;">
        Thank you for registering. Please verify your email address to activate your account.
        This link will expire in <b>1 hour</b>.
      </p>

      <div style="text-align:center; margin:30px 0;">
        <a href="{verify_link}"
           style="
              background:#2563eb;
              color:#ffffff;
              padding:14px 24px;
              text-decoration:none;
              border-radius:6px;
              font-weight:bold;
              display:inline-block;
           ">
          Verify Email
        </a>
      </div>

      <p style="font-size:13px; color:#666;">
        If the button doesn't work, copy and paste this link:
      </p>

      <p style="font-size:12px; word-break:break-all; color:#2563eb;">
        {verify_link}
      </p>

      <hr style="margin:30px 0; border:none; border-top:1px solid #eee;">

      <p style="font-size:12px; color:#888;">
        If you didn’t create this account, you can ignore this email.
      </p>

    </div>

    <div style="background:#f9fafb; padding:15px; text-align:center; font-size:12px; color:#999;">
      © 2026 {settings.NAMEMAIL}. All rights reserved.
    </div>

  </div>

</body>
</html>
"""

def send_verification_email(to_email: str, name: str, token: str, protocol: str = "http://" , domain: str = settings.DOMAIN):
    url = settings.EMAILURL

    verify_link = f"{protocol}{domain}/api/v1/users/verify_email?token={token}"

    html_content = build_verification_email(name, verify_link)

    headers = {
        "Authorization": f"Bearer {settings.EMAILTOKEN}",
        "Content-Type": "application/json"
    }

    data = {
        "from": {
            "email": settings.COMEMAIL,
            "name": settings.NAMEMAIL
        },
        "to": [
            {
                "email": to_email,
                "name": name
            }
        ],
        "subject": "Verify your email",
        "html": html_content
    }

    response = requests.post(url, headers=headers, json=data)

    return {
        "status_code": response.status_code,
        "response": response.text
    }


def build_welcome_email(endpoint: str, name: str):
    return f"""
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Welcome</title>
</head>

<body style="margin:0; padding:0; font-family:Arial, sans-serif; background-color:#f4f6f8;">

  <div style="max-width:600px; margin:40px auto; background:#ffffff; border-radius:10px; overflow:hidden; box-shadow:0 4px 20px rgba(0,0,0,0.08);">

    <!-- Header -->
    <div style="background:#16a34a; padding:20px; text-align:center;">
      <h2 style="color:#ffffff; margin:0;">Welcome to {settings.NAMEMAIL}</h2>
    </div>

    <!-- Body -->
    <div style="padding:30px; color:#333;">

      <h3 style="margin-top:0;">Hello {name}, 🎉</h3>

      <p style="font-size:15px; line-height:1.6;">
        Welcome aboard! Your account has been created successfully.
      </p>

      <p style="font-size:15px; line-height:1.6;">
        You can now access all features of our platform. We're excited to have you with us.
      </p>

      <div style="text-align:center; margin:30px 0;">
        <a href="{endpoint}"
           style="
              background:#16a34a;
              color:#ffffff;
              padding:14px 24px;
              text-decoration:none;
              border-radius:6px;
              font-weight:bold;
              display:inline-block;
           ">
          Go to Dashboard
        </a>
      </div>

      <hr style="margin:30px 0; border:none; border-top:1px solid #eee;">

      <p style="font-size:12px; color:#888;">
        If you have any questions, feel free to contact our support team.
      </p>

    </div>

    <!-- Footer -->
    <div style="background:#f9fafb; padding:15px; text-align:center; font-size:12px; color:#999;">
      © 2026 {settings.NAMEMAIL}. All rights reserved.
    </div>

  </div>

</body>
</html>
"""


def send_welcome_email(to_email: str, name: str):
    url = settings.EMAILURL

    html_content = build_welcome_email(name)

    headers = {
        "Authorization": f"Bearer {settings.EMAILTOKEN}",
        "Content-Type": "application/json"
    }

    data = {
        "from": {
            "email": settings.COMEMAIL,
            "name": settings.NAMEMAIL
        },
        "to": [
            {
                "email": to_email,
                "name": name
            }
        ],
        "subject": "Welcome to our platform 🎉",
        "html": html_content
    }

    response = requests.post(url, headers=headers, json=data)

    return {
        "status_code": response.status_code,
        "response": response.text
    }