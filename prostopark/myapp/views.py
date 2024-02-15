from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.views.generic import View
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password
from django.utils.http import urlsafe_base64_decode
from .utils import send_email_for_verify, user_exists, unauthenticated_required, self_unauthenticated_required, token_generator
from .models import Profile, Car


class ProfileView(LoginRequiredMixin, View):
    login_url = "login"

    def get(self, request):
        return render(
            request,
            "profile.html",
            {"cars": Car.objects.exclude(pk=self.request.user.car.pk)},
        )

    def post(self, request):
        username = request.POST["username"]
        email = request.POST["email"]
        car = request.POST["car"]

        user: Profile = self.request.user
        user.username = username

        try:
            user.car = Car.objects.get(pk=car)
        except:
            user.car = Car.objects.get(pk=1)

        user_ex = user_exists(email)

        if user.email != email and not user_ex:
            user.email = email
            user.email_verify = False
            user.save()
            send_email_for_verify(
                request,
                user,
                "verify_email.html",
                "Запрос на смену адреса электронной почты",
            )
            # logout(request)
            return redirect("confirm_email")

        elif user.email != email and user_ex:
            user.save()
            return render(
                request,
                "profile.html",
                {
                    "email_change_error_message": "Пользователь с данным адресом электронной почты уже существует.",
                    "cars": Car.objects.exclude(pk=self.request.user.car.pk),
                },
            )

        user.save()
        return render(
            request,
            "profile.html",
            {"cars": Car.objects.exclude(pk=self.request.user.car.pk)},
        )


class ForgotPasswordView(View):
    def get(self, request):
        return render(request, "forgot_password.html")

    def post(self, request):
        email = request.POST["email"]
        if user_exists(email):
            user = Profile.objects.get(email=email)
            send_email_for_verify(
                request, user, "password_reset_email.html", "Запрос на смену пароля"
            )
            return redirect("password_reset")
        else:
            return render(
                request,
                "forgot_password.html",
                {"forgot_password_error_message": "Неверный email."},
            )


class EmailVerify(View):

    def get(self, request, uidb64, token):
        user = self.get_user(uidb64)

        if user is not None and token_generator.check_token(user, token):
            user.email_verify = True
            user.save()
            login(request, user)
            return redirect("profile")
        return redirect("invalid_verify")

    @staticmethod
    def get_user(uidb64):
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = Profile._default_manager.get(pk=uid)
        except (
            TypeError,
            ValueError,
            OverflowError,
            Profile.DoesNotExist,
            ValidationError,
        ):
            user = None
        return user


class MyPasswordResetView(View):

    def get(self, request, uidb64, token):
        user = EmailVerify.get_user(uidb64)

        if user is not None and token_generator.check_token(user, token):
            # user.email_verify = True
            # user.save()
            # login(request, user)
            return render(request, "password_reset.html")
        return redirect("invalid_verify")

    def post(self, request, uidb64, token):
        user = EmailVerify.get_user(uidb64)
        if user is not None and token_generator.check_token(user, token):
            password1 = request.POST["password"]
            password2 = request.POST["confirm_password"]

            if password1 != password2:
                # Пароли не совпадают, вернуть сообщение об ошибке
                return render(
                    request,
                    "password_reset.html",
                    {"password_reset_error_message": ["Пароли не совпадают."]},
                )

            user.set_password(password1)
            user.save()
            login(request, user)
            return redirect("profile")
        return redirect("invalid_verify")


@unauthenticated_required("list")
def user_register(request):
    if request.method == "POST":
        password1 = request.POST["password"]
        password2 = request.POST["confirm_password"]

        if password1 != password2:
            # Пароли не совпадают, вернуть сообщение об ошибке
            return render(
                request,
                "enter.html",
                {"registration_error_message": ["Пароли не совпадают."]},
            )

        # Пароли совпадают, перенаправить на страницу /list
        email = request.POST["email"]

        if user_exists(email):
            return render(
                request,
                "enter.html",
                {
                    "registration_error_message": [
                        "Пользователь с данным адресом электронной почты уже существует."
                    ]
                },
            )

        try:
            validate_password(password1)
        except ValidationError as e:
            errors = e.messages
            return render(request, "enter.html", {"registration_error_message": errors})

        username = request.POST["username"]
        user = Profile(username=username, email=email)
        user.set_password(password1)
        user.save()

        user = authenticate(request, email=email, password=password1)
        send_email_for_verify(
            request, user, "verify_email.html", "Подтверждение адреса электронной почты"
        )
        # login(request, user)
        return redirect("confirm_email")

    # Если это GET-запрос, просто отобразить страницу
    return render(request, "enter.html")


class UserRegisterView(View):

    @self_unauthenticated_required("list")
    def get(self, request):
        return render(request, "enter.html")

    @self_unauthenticated_required("list")
    def post(self, request):
        password1 = request.POST["password"]
        password2 = request.POST["confirm_password"]

        if password1 != password2:
            # Пароли не совпадают, вернуть сообщение об ошибке
            return render(
                request,
                "enter.html",
                {"registration_error_message": ["Пароли не совпадают."]},
            )

        # Пароли совпадают, перенаправить на страницу /list
        email = request.POST["email"]

        if user_exists(email):
            return render(
                request,
                "enter.html",
                {
                    "registration_error_message": [
                        "Пользователь с данным адресом электронной почты уже существует."
                    ]
                },
            )

        try:
            validate_password(password1)
        except ValidationError as e:
            errors = e.messages
            return render(request, "enter.html", {"registration_error_message": errors})

        username = request.POST["username"]
        user = Profile(username=username, email=email)
        user.set_password(password1)
        user.save()
        user = authenticate(request, email=email, password=password1)
        login(request, user)
        send_email_for_verify(
            request, user, "verify_email.html", "Подтверждение адреса электронной почты"
        )
        return redirect("confirm_email")


@unauthenticated_required("list")
def user_login(request):
    if request.method == "POST":
        email = request.POST["email"]
        password = request.POST["password"]
        user = authenticate(request, email=email, password=password)
        if user:
            if user.email_verify:
                # Вход успешен, перенаправление на другую страницу
                login(request, user)
                return redirect("list")
            else:
                # Email не подтверждён, говорим об этом
                send_email_for_verify(
                    request,
                    user,
                    "verify_email.html",
                    "Подтверждение адреса электронной почты",
                )
                return redirect("confirm_email")
        else:
            # Не удалось войти, выдайте сообщение об ошибке
            return render(
                request,
                "enter.html",
                {"login_error_message": "Неверный email или пароль."},
            )

    return render(request, "enter.html")


class UserLoginView(View):

    @self_unauthenticated_required("list")
    def get(self, request):
        return render(request, "enter.html")

    @self_unauthenticated_required("list")
    def post(self, request):
        email = request.POST["email"]
        password = request.POST["password"]
        user = authenticate(request, email=email, password=password)
        if user:
            login(request, user)
            if user.email_verify:
                # Вход успешен, перенаправление на другую страницу
                return redirect("list")
            else:
                # Email не подтверждён, говорим об этом
                send_email_for_verify(
                    request,
                    user,
                    "verify_email.html",
                    "Подтверждение адреса электронной почты",
                )
                return redirect("confirm_email")
        else:
            # Не удалось войти, выдайте сообщение об ошибке
            return render(
                request,
                "enter.html",
                {"login_error_message": "Неверный email или пароль."},
            )


@login_required
def user_logout(request):
    logout(request)
    return redirect("login")


def home(request):
    return render(request, "index.html")


def list(request):
    return render(request, "list.html")
