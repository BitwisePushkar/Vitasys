from django.core.mail import send_mail
from django.conf import settings
import logging
from celery import shared_task

logger = logging.getLogger(__name__)

@shared_task
def send_otp_email_task(email, otp, email_type):
    subject_map = {
        'verification': '🔐 Verify Your Medtrax Account - OTP Code',
        'reset': '🔑 Password Reset Request - OTP Code',
        'resend': '📧 New Verification Code - Medtrax'
    }
    
    message_map = {
        'verification': {
            'title': 'Email Verification',
            'intro': 'Thank you for registering with Medtrax Healthcare!',
            'instruction': 'To complete your registration, please use the OTP code below:'
        },
        'reset': {
            'title': 'Password Reset',
            'intro': 'We received a request to reset your password.',
            'instruction': 'To reset your password, please use the OTP code below:'
        },
        'resend': {
            'title': 'New Verification Code',
            'intro': 'You requested a new verification code.',
            'instruction': 'Here is your new OTP code:'
        }
    }
    
    subject = subject_map.get(email_type, '🔐 Your OTP Code - Medtrax')
    message_content = message_map.get(email_type, {
        'title': 'Verification Code',
        'intro': 'You requested an OTP code.',
        'instruction': 'Your OTP code is:'
    })

    html_message = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body {{ 
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                line-height: 1.6; 
                color: #333; 
                margin: 0;
                padding: 0;
                background-color: #f4f4f4;
            }}
            .container {{ 
                max-width: 600px; 
                margin: 20px auto; 
                background-color: white;
                border-radius: 10px;
                overflow: hidden;
                box-shadow: 0 0 20px rgba(0,0,0,0.1);
            }}
            .header {{ 
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white; 
                padding: 30px 20px; 
                text-align: center; 
            }}
            .header h1 {{
                margin: 0;
                font-size: 28px;
                font-weight: 600;
            }}
            .content {{ 
                padding: 40px 30px; 
            }}
            .content h2 {{
                color: #667eea;
                margin-top: 0;
                font-size: 24px;
            }}
            .content p {{
                margin: 15px 0;
                font-size: 16px;
            }}
            .otp-box {{ 
                text-align: center;
                margin: 30px 0;
            }}
            .otp {{ 
                font-size: 36px; 
                font-weight: bold; 
                color: #667eea; 
                padding: 20px 40px; 
                background-color: #f8f9ff; 
                border: 2px dashed #667eea;
                border-radius: 10px; 
                display: inline-block;
                letter-spacing: 8px;
            }}
            .warning {{
                background-color: #fff3cd;
                border-left: 4px solid #ffc107;
                padding: 15px;
                margin: 20px 0;
                border-radius: 5px;
            }}
            .warning p {{
                margin: 5px 0;
                color: #856404;
                font-size: 14px;
            }}
            .security-note {{
                background-color: #f8f9fa;
                padding: 20px;
                border-radius: 5px;
                margin-top: 20px;
            }}
            .security-note h3 {{
                margin-top: 0;
                color: #495057;
                font-size: 16px;
            }}
            .security-note ul {{
                margin: 10px 0;
                padding-left: 20px;
            }}
            .security-note li {{
                margin: 8px 0;
                color: #6c757d;
                font-size: 14px;
            }}
            .footer {{ 
                text-align: center; 
                padding: 20px;
                background-color: #f8f9fa;
                color: #6c757d; 
                font-size: 13px;
                border-top: 1px solid #e9ecef;
            }}
            .footer p {{
                margin: 5px 0;
            }}
            .footer a {{
                color: #667eea;
                text-decoration: none;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🏥 Medtrax Healthcare</h1>
            </div>
            <div class="content">
                <h2>{message_content['title']}</h2>
                <p>Hello,</p>
                <p>{message_content['intro']}</p>
                <p>{message_content['instruction']}</p>
                
                <div class="otp-box">
                    <div class="otp">{otp}</div>
                </div>
                
                <div class="warning">
                    <p><strong>⚠️ Important:</strong></p>
                    <p>• This OTP is valid for <strong>3 minutes only</strong></p>
                    <p>• Do not share this code with anyone</p>
                    <p>• Medtrax will never ask for your OTP via phone or email</p>
                </div>
                
                <div class="security-note">
                    <h3>🔒 Security Tips:</h3>
                    <ul>
                        <li>If you didn't request this code, please ignore this email and secure your account</li>
                        <li>Never share your OTP with anyone, including Medtrax staff</li>
                        <li>Always verify you're on the official Medtrax website</li>
                    </ul>
                </div>
                
                <p style="margin-top: 30px;">If you need assistance, please contact our support team.</p>
            </div>
            <div class="footer">
                <p><strong>Medtrax Healthcare</strong></p>
                <p>&copy; 2024 Medtrax. All rights reserved.</p>
                <p>This is an automated message. Please do not reply to this email.</p>
            </div>
        </div>
    </body>
    </html>
    """
 

    text_message = f"""
    ═══════════════════════════════════════
    🏥 MEDTRAX HEALTHCARE
    ═══════════════════════════════════════
    
    {message_content['title'].upper()}
    
    Hello,
    
    {message_content['intro']}
    {message_content['instruction']}
    
    ┌─────────────────────────┐
    │   YOUR OTP CODE: {otp}   │
    └─────────────────────────┘
    
    ⚠️ IMPORTANT:
    • Valid for 3 MINUTES ONLY
    • Do NOT share with anyone
    • Medtrax will NEVER ask for your OTP
    
    🔒 SECURITY TIPS:
    • Didn't request this? Ignore this email and secure your account
    • Never share OTP with anyone, including Medtrax staff
    • Always verify you're on the official Medtrax website
    
    ═══════════════════════════════════════
    
    Need help? Contact our support team.
    
    Best regards,
    Medtrax Healthcare Team
    
    ---
    © 2024 Medtrax. All rights reserved.
    This is an automated message - do not reply.
    """
    
    try:
        send_mail(
            subject=subject,
            message=text_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email],
            fail_silently=False,
            html_message=html_message
        )
        logger.info(f"✅ OTP email ({email_type}) sent successfully to {email}")
        return {
            'success': True,
            'email': email,
            'type': email_type
        }
    except Exception as e:
        logger.error(f"❌ Failed to send OTP email ({email_type}) to {email}: {str(e)}")
        raise Exception(f"Email delivery failed: {str(e)}")