import threading
import logging
from django.core.mail import EmailMultiAlternatives
from django.conf import settings
import boto3
from botocore.exceptions import ClientError
import uuid
from django.conf import settings

logger = logging.getLogger(__name__)
ALLOWED_IMAGE_TYPES = {'image/jpeg': 'jpg','image/png' : 'png','image/webp': 'webp',}
MAX_IMAGE_SIZE_BYTES = 5 * 1024 * 1024 

def upload_image(user, image_file) -> str:
    content_type = image_file.content_type
    if content_type not in ALLOWED_IMAGE_TYPES:
        raise ValueError(f"Invalid file type '{content_type}'. "f"Allowed types: JPEG, PNG, WEBP.")
    if image_file.size > MAX_IMAGE_SIZE_BYTES:
        raise ValueError(f"File size {round(image_file.size / (1024*1024), 2)}MB "f"exceeds the 5MB limit.")
    ext = ALLOWED_IMAGE_TYPES[content_type]
    s3_key = f"profile-images/{user.role}/{user.id}/{uuid.uuid4()}.{ext}"
    image_file.seek(0)
    file_bytes = image_file.read()
    try:
        s3_client = boto3.client('s3',aws_access_key_id = settings.AWS_ACCESS_KEY_ID,aws_secret_access_key = settings.AWS_SECRET_ACCESS_KEY,
                                 region_name = settings.AWS_S3_REGION_NAME,)
        s3_client.put_object(Bucket = settings.AWS_STORAGE_BUCKET_NAME,Key = s3_key,Body = file_bytes,ContentType = content_type,)
    except ClientError as e:
        raise ValueError(f"S3 upload failed: {e.response['Error']['Message']}")
    except Exception as e:
        raise ValueError(f"S3 upload failed: {str(e)}")
    public_url = (f"https://{settings.AWS_STORAGE_BUCKET_NAME}"f".s3.{settings.AWS_S3_REGION_NAME}"f".amazonaws.com/{s3_key}")
    return public_url

def _build_email_content(otp: str, email_type: str) -> tuple[str, str, str]:
    config_map = {
        'verification': {
            'subject': 'Verify your Vitesys account',
            'title':   'Email Verification',
            'intro':   'Thank you for signing up with Vitesys Healthcare.',
            'action':  'To complete your registration, use the OTP below:',
        },
        'reset': {
            'subject': 'Reset your Vitesys password',
            'title':   'Password Reset',
            'intro':   'We received a request to reset your password.',
            'action':  'Use the OTP below to reset your password:',
        },
        'resend': {
            'subject': 'New verification code — Vitesys',
            'title':   'New Verification Code',
            'intro':   'You requested a new verification code.',
            'action':  'Here is your updated OTP:',
        },
    }
    c = config_map.get(email_type, config_map['verification'])
    plain = f"""
{c['title'].upper()}

{c['intro']}
{c['action']}

    OTP Code: {otp}

This code is valid for 3 minutes only.
Do not share it with anyone — Vitesys will never ask for your OTP.

If you didn't request this, please ignore this email.

— Vitesys Healthcare
"""
    html = f"""
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    body {{
      margin: 0; padding: 0;
      background-color: #f4f6f8;
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      color: #333;
    }}
    .wrapper {{
      max-width: 560px;
      margin: 40px auto;
      background: #ffffff;
      border-radius: 12px;
      overflow: hidden;
      box-shadow: 0 4px 20px rgba(0,0,0,0.08);
    }}
    .header {{
      background: linear-gradient(135deg, #2c7be5, #1a5cbf);
      padding: 32px 24px;
      text-align: center;
    }}
    .header h1 {{
      margin: 0;
      color: #ffffff;
      font-size: 22px;
      font-weight: 700;
      letter-spacing: 0.5px;
    }}
    .header p {{
      margin: 6px 0 0;
      color: #cde0ff;
      font-size: 13px;
    }}
    .body {{
      padding: 36px 32px;
    }}
    .body h2 {{
      margin: 0 0 8px;
      font-size: 20px;
      color: #1a1a2e;
    }}
    .body p {{
      font-size: 15px;
      line-height: 1.6;
      color: #555;
      margin: 12px 0;
    }}
    .otp-box {{
      text-align: center;
      margin: 28px 0;
    }}
    .otp {{
      display: inline-block;
      font-size: 38px;
      font-weight: 800;
      letter-spacing: 12px;
      color: #2c7be5;
      background: #f0f6ff;
      border: 2px dashed #2c7be5;
      border-radius: 10px;
      padding: 16px 32px;
    }}
    .expiry {{
      text-align: center;
      font-size: 13px;
      color: #888;
      margin-top: -10px;
    }}
    .warning {{
      background: #fff8e1;
      border-left: 4px solid #f5a623;
      border-radius: 6px;
      padding: 14px 16px;
      margin-top: 24px;
      font-size: 13px;
      color: #7a5c00;
      line-height: 1.6;
    }}
    .footer {{
      background: #f4f6f8;
      text-align: center;
      padding: 20px;
      font-size: 12px;
      color: #999;
      border-top: 1px solid #e8ecf0;
    }}
  </style>
</head>
<body>
  <div class="wrapper">

    <div class="header">
      <h1>🏥 Vitesys Healthcare</h1>
      <p>Secure Healthcare Management</p>
    </div>

    <div class="body">
      <h2>{c['title']}</h2>
      <p>{c['intro']}</p>
      <p>{c['action']}</p>

      <div class="otp-box">
        <div class="otp">{otp}</div>
      </div>
      <p class="expiry">⏱ Valid for <strong>3 minutes</strong> only</p>

      <div class="warning">
        <strong>⚠️ Security Notice</strong><br>
        Never share this code with anyone — including Vitesys staff.<br>
        If you did not request this, please ignore this email.
      </div>
    </div>

    <div class="footer">
      © 2024 Vitesys Healthcare. All rights reserved.<br>
      This is an automated message — please do not reply.
    </div>

  </div>
</body>
</html>
"""
    return c['subject'], plain.strip(), html.strip()

def _send_otp_email(email: str, otp: str, email_type: str) -> None:
    try:
        subject, plain_body, html_body = _build_email_content(otp, email_type)
        msg = EmailMultiAlternatives(
            subject=subject,
            body=plain_body,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[email],
        )
        msg.attach_alternative(html_body, "text/html")
        msg.send(fail_silently=False)
        logger.info(f"OTP email ({email_type}) sent to {email}")

    except Exception as e:
        logger.error(f"Failed to send OTP email ({email_type}) to {email}: {e}")

def send_otp_email(email: str, otp: str, email_type: str) -> None:
    thread = threading.Thread(
        target=_send_otp_email,
        args=(email, otp, email_type),
        daemon=True,
    )
    thread.start()