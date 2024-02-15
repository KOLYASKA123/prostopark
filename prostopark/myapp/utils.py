from django.core.mail import EmailMessage
from django.shortcuts import redirect
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.contrib.auth.tokens import default_token_generator as token_generator
from django.template.loader import render_to_string
from .models import Profile


def user_exists(email):
    return Profile.objects.filter(email=email).exists()


def self_unauthenticated_required(url_path_name: str):
    """Декоратор перенаправления для методов классов."""

    def decorator(func):
        def wrapper(self, request, *args, **kwargs):
            if request.user.is_authenticated:
                return redirect(url_path_name)
            else:
                return func(self, request, *args, **kwargs)

        return wrapper

    return decorator


def unauthenticated_required(url_path_name: str):
    """Декоратор перенаправления для методов классов."""

    def decorator(func):
        def wrapper(request, *args, **kwargs):
            if request.user.is_authenticated:
                return redirect(url_path_name)
            else:
                return func(request, *args, **kwargs)

        return wrapper

    return decorator


def send_email_for_verify(request, user: Profile, html_template, email_header):
    current_site = get_current_site(request)
    site_name = current_site.name
    domain = current_site.domain

    context = {
        "domain": domain,
        "site_name": site_name,
        "uid": urlsafe_base64_encode(force_bytes(user.pk)),
        "user": user,
        "token": token_generator.make_token(user),
        "protocol": "https",
    }

    message = render_to_string(html_template, context=context)

    email = EmailMessage(email_header, message, to=[user.email])

    email.send()
