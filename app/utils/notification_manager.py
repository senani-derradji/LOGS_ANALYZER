import httpx
from app.core.config import settings


# =========================
# VERIFY EMAIL HTML
# =========================
def build_verification_email(name: str, verify_link: str):
    return f"""
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Verify Your Email</title>
</head>

<body style="font-family:Arial;background:#f4f6f8;margin:0;padding:0;">

  <div style="max-width:600px;margin:40px auto;background:#fff;border-radius:10px;overflow:hidden;">

    <div style="background:#111827;padding:20px;text-align:center;">
      <h2 style="color:white;">Verify Your Email</h2>
    </div>

    <div style="padding:30px;">
      <h3>Hello {name},</h3>

      <p>Please verify your email. Link expires in 1 hour.</p>

      <div style="text-align:center;margin:30px 0;">
        <a href="{verify_link}"
           style="background:#2563eb;color:white;padding:14px 24px;text-decoration:none;border-radius:6px;">
          Verify Email
        </a>
      </div>

      <p style="font-size:12px;word-break:break-all;color:#2563eb;">
        {verify_link}
      </p>
    </div>

  </div>

</body>
</html>
"""


# =========================
# SEND VERIFY EMAIL (ASYNC)
# =========================
async def send_verification_email(to_email: str, name: str, token: str, protocol: str = "https://"):
    url = settings.EMAILURL

    verify_link = f"{protocol}{settings.DOMAIN}/api/v1/users/verify_email?token={token}"

    html_content = build_verification_email(name, verify_link)

    data = {
        "from": {
            "email": settings.COMEMAIL,
            "name": settings.NAMEMAIL
        },
        "to": [{
            "email": to_email,
            "name": name
        }],
        "subject": "Verify your email",
        "html": html_content
    }

    async with httpx.AsyncClient(timeout=10) as client:
        response = await client.post(
            url,
            headers={
                "Authorization": f"Bearer {settings.EMAILTOKEN}",
                "Content-Type": "application/json"
            },
            json=data
        )

    return response.json()


# =========================
# WELCOME EMAIL HTML
# =========================
def build_welcome_email(name: str, endpoint: str = settings.DOMAIN):
    return f"""
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Welcome</title>
</head>

<body style="font-family:Arial;background:#f4f6f8;margin:0;padding:0;">

  <div style="max-width:600px;margin:40px auto;background:#fff;border-radius:10px;overflow:hidden;">

    <div style="background:#16a34a;padding:20px;text-align:center;">
      <h2 style="color:white;">Welcome</h2>
    </div>

    <div style="padding:30px;">
      <h3>Hello {name} 🎉</h3>

      <p>Your account is ready.</p>

      <div style="text-align:center;margin:30px 0;">
        <a href="{endpoint}"
           style="background:#16a34a;color:white;padding:14px 24px;text-decoration:none;border-radius:6px;">
          Dashboard
        </a>
      </div>

    </div>

  </div>

</body>
</html>
"""


# =========================
# SEND WELCOME EMAIL (ASYNC)
# =========================
async def send_welcome_email(to_email: str, name: str):
    url = settings.EMAILURL

    html_content = build_welcome_email(name)

    data = {
        "from": {
            "email": settings.COMEMAIL,
            "name": settings.NAMEMAIL
        },
        "to": [{
            "email": to_email,
            "name": name
        }],
        "subject": "Welcome 🎉",
        "html": html_content
    }

    async with httpx.AsyncClient(timeout=10) as client:
        response = await client.post(
            url,
            headers={
                "Authorization": f"Bearer {settings.EMAILTOKEN}",
                "Content-Type": "application/json"
            },
            json=data
        )

    return response.json()


import httpx
from app.core.config import settings


def build_reset_password_email(name: str, reset_link: str):
    return f"""
<!DOCTYPE html>
<html>
<head>
  <title>Reset Password</title>
</head>

<body style="font-family:Arial;background:#f4f6f8;display:flex;justify-content:center;align-items:center;height:100vh;">

  <div style="background:white;padding:30px;border-radius:10px;width:400px;box-shadow:0 4px 20px rgba(0,0,0,0.1);">

    <h2 style="color:#dc2626;">Reset Password</h2>

    <p>Hello {name},</p>
    <p>Click below to reset your password:</p>

    <a href="{reset_link}"
       style="display:inline-block;padding:12px 20px;background:#dc2626;color:white;text-decoration:none;border-radius:6px;">
       Reset Password
    </a>

    <p style="font-size:12px;word-break:break-all;margin-top:20px;">
      {reset_link}
    </p>

  </div>

</body>
</html>
"""


async def send_reset_password_email(to_email: str, name: str, token: str):
    url = settings.EMAILURL

    reset_link = f"{settings.DOMAIN if settings.DOMAIN.startswith('http') else 'http://' + settings.DOMAIN}/api/v1/users/reset-password-page?token={token}"

    html_content = build_reset_password_email(name, reset_link)

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
        "subject": "Reset Your Password",
        "html": html_content
    }

    async with httpx.AsyncClient(timeout=10) as client:
        response = await client.post(
            url,
            headers={
                "Authorization": f"Bearer {settings.EMAILTOKEN}",
                "Content-Type": "application/json"
            },
            json=data
        )

    try:
        result = response.json()
    except Exception:
        result = response.text

    return {
        "status_code": response.status_code,
        "response": result
    }