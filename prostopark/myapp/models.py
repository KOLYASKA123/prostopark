from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.validators import UnicodeUsernameValidator

# Create your models here.


class Car(models.Model):
    body = models.CharField(max_length=50, unique=True, null=True)

    def __str__(self):
        return f"{self.body}"


default_car = 2


class Profile(AbstractUser):
    username = models.CharField(
        _("username"),
        max_length=150,
        help_text=_(
            "Required. 150 characters or fewer. Letters, digits and @/./+/-/_ only."
        ),
        validators=[UnicodeUsernameValidator()],
    )
    email = models.EmailField(_("email address"), blank=True, unique=True)
    email_verify = models.BooleanField(default=False)
    car = models.ForeignKey(
        "Car", on_delete=models.SET_NULL, null=True, blank=True, default=default_car
    )

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["username"]


# class Camera(models.Model):
#     href = models.URLField(_("url address"))
