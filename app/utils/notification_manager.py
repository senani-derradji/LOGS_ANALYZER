import httpx
from app.core.config import settings


def build_verification_email(name: str, token: str):
    from app.core.config import settings
    protocol = "https://" if settings.ENVIRONMENT == "production" else "http://"
    domain = settings.DOMAIN if settings.DOMAIN else "localhost:8000"
    verify_link = f"{protocol}{domain}/?verify_token={token}"

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

      <p>Click the button below to verify your email address. This link expires in 1 hour.</p>

      <div style="text-align:center;margin:30px 0;">
        <a href="{verify_link}"
           style="background:#2563eb;color:white;padding:14px 24px;text-decoration:none;border-radius:6px;font-weight:bold;">
          Verify Email
        </a>
      </div>

      <p style="font-size:12px;word-break:break-all;color:#6b7280;margin-top:20px;">
        If the button doesn't work, copy and paste this URL into your browser:<br>
        <span style="color:#2563eb;">{verify_link}</span>
      </p>

      <p style="font-size:12px;color:#9ca3af;margin-top:30px;">
        If you didn't create an account, you can safely ignore this email.
      </p>

    </div>

  </div>

</body>
</html>
"""


async def send_verification_email(to_email: str, name: str, token: str):
    url = settings.EMAILURL

    html_content = build_verification_email(name, token)

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

    # Safely handle non-JSON responses from email service
    try:
        return response.json()
    except Exception:
        return {"status": response.status_code, "text": response.text[:200]}


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

      </div>

    </div>

  </div>

</body>
</html>
"""


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

    # Safely handle non-JSON responses from email service
    try:
        return response.json()
    except Exception:
        return {"status": response.status_code, "text": response.text[:200]}


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


def build_invite_email(name: str, invite_link: str):
    return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>You're Invited!</title>
</head>
<body style="font-family:Arial,Helvetica,sans-serif;background:#f4f6f8;margin:0;padding:0;">

    <div style="max-width:600px;margin:40px auto;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,0.1);">

        <div style="background:#111827;padding:30px 20px;text-align:center;">
            <h1 style="color:#fff;margin:0;font-size:28px;">You're Invited! 🎉</h1>
        </div>

        <div style="padding:40px 30px;">

            <h3>Hello {name},</h3>

            <p style="font-size:16px;color:#374151;">
                You've been invited to join the <strong>Logs Analyzer</strong> platform!
                Click the button below to accept your invitation and create your account.
            </p>

            <div style="text-align:center;margin:30px 0;">
                <a href="{invite_link}"
                   style="background:#2563eb;color:#ffffff;padding:16px 32px;text-decoration:none;border-radius:8px;font-size:16px;font-weight:bold;display:inline-block;">
                    Accept Invitation
                </a>
            </div>

            <div style="background:#f3f4f6;padding:15px;border-left:4px solid #2563eb;margin-top:30px;">
                <p style="margin:0;font-size:14px;color:#6b7280;">
                    <strong>Note:</strong> This link expires in 24 hours. If you don't use it in time, you can request a new invitation.
                </p>
            </div>

            <p style="font-size:13px;color:#9ca3af;margin-top:30px;text-align:center;">
                If you didn't expect this invitation, you can safely ignore this email.
            </p>

        </div>

    </div>

</body>
</html>
"""


async def send_invite_email(to_email: str, name: str, invite_link: str):
    url = settings.EMAILURL

    html_content = build_invite_email(name, invite_link)
    print("invite_link: ", invite_link)
    print("name: ", name)
    print("to_email: ", to_email)

    data = {
        "from": {
            "email": settings.COMEMAIL,
            "name": settings.NAMEMAIL
        },
        "to": [{
            "email": to_email,
            "name": name
        }],
        "subject": "You're Invited to Logs Analyzer 🎉",
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

    # Safely handle non-JSON responses from email service
    try:
        return response.json()
    except Exception:
        return {"status": response.status_code, "text": response.text[:200]}