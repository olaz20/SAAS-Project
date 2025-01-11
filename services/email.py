import requests
import random
from django.conf import settings
from django.http import JsonResponse
from django.core.cache import cache
from django.core.signing import BadSignature, Signer
from django.core.mail import EmailMessage, send_mail
from django.urls import reverse
from django.utils.html import format_html
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import (
    DjangoUnicodeDecodeError,
    smart_bytes,
    smart_str,
)
from django.utils.crypto import get_random_string
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.sites.shortcuts import get_current_site

def send_email(to_email, subject, html_content):
    API_URL = "https://api.mailersend.com/v1/email"
    headers = {
        "Authorization": f"Bearer {settings.MAILERSEND_API_KEY}",
        "Content-Type": "application/json",
    }
    payload = {
        "from": {
            "email": settings.MAILERSEND_FROM_EMAIL,
            "name": settings.MAILERSEND_FROM_NAME,
        },
        "to": [{"email": to_email}],
        "subject": subject,
        "html": html_content,
    }
    response = requests.post(API_URL, json=payload, headers=headers)
    if response.status_code == 202:
        return {"status": "success", "message": "Email sent successfully"}
    else:
        return {"status": "error", "message": response.json()}



def send_signup_verification_email(request, user_data):
    auth_code = random.randint(100000, 999999)
    first_name = user_data["first_name"]
    email = user_data["email"]
    cache.set(f"auth_code_{email}", auth_code, timeout=600)
    cache.set(f"user_data_{email}", user_data, timeout=600)
    signer = Signer()
    signed_data = signer.sign(email)
    current_site = get_current_site(request).domain

    relative_link = reverse("email-verify")
    absurl = f"http://{current_site}{relative_link}?token={signed_data}"
    email_body = format_html(
        """
        <p>Hi {},</p>
        <p>Thank you for signing up! Please verify your email by clicking the button below:</p>
        <a href="{}" style="
            display: inline-block;
            padding: 10px 20px;
            font-size: 16px;
            color: #fff;
            background-color: #28a745;
            text-decoration: none;
            border-radius: 5px;
        ">
            Verify Email
        </a>
        <p>Alternatively, you can use the authentication code below to verify your email:</p>
        <h3 style="color: #333;">{}</h3>
        <p>If you didn't sign up for this account, please ignore this email.</p>
        """,
        first_name,
        absurl,
        auth_code
    )
    email_message = EmailMessage(
        subject="Verify your email and authentication code",
        body=email_body,
        to=[email],
    )
    email_message.content_subtype = "html"  # Specify HTML format for the email
    email_message.send()

    return True

def send_password_reset_email(request, user_obj):
    uidb64 = urlsafe_base64_encode(smart_bytes(user_obj.id))
    token = PasswordResetTokenGenerator().make_token(user_obj)

    reset_code = get_random_string(length=6, allowed_chars="0123456789")
    cache.set(
        f"password_reset_code_{user_obj.email}", reset_code, timeout=900
    )  # Valid for 15 minutes

    current_site = get_current_site(request=request).domain
    relative_link = reverse(
        "password-reset-confirm",
        kwargs={"uidb64": uidb64, "token": token},
    )
    redirect_url = request.data.get("redirect_url", "")
    absurl = (
        f"http://{current_site}{relative_link}?redirect_url={redirect_url}"
    )

    email_body = format_html(
        """
        <p>Hello,</p>
        <p>Click the button below to reset your password:</p>
        <a href="{}" style="
            display: inline-block;
            padding: 10px 20px;
            font-size: 16px;
            color: #fff;
            background-color: #007bff;
            text-decoration: none;
            border-radius: 5px;
        ">
            Reset Password
        </a>
        <p>Alternatively, use this code to reset your password: <strong>{}</strong></p>
        <p>If you didn't request a password reset, please ignore this email.</p>
        """,
        absurl,
        reset_code
    )


    data = {
        "email_body": email_body,
        "to_email": user_obj.email,
        "email_subject": "Reset Your Password",
    }
    email = EmailMessage(
        subject=data["email_subject"],
        body=data["email_body"],
        to=[data["to_email"]],
    )
    email.content_subtype = "html"  # Specify that the email is in HTML format
    email.send()

    return True
