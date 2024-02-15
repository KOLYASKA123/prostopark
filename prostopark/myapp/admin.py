from django.contrib import admin
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import Profile, Car

# Register your models here.


class ProfileAdmin(BaseUserAdmin):
    # Этот код был взят из модели UserAdmin. list_display и fieldsets изменены в соответствии с требованием к проекту
    list_display = (
        "username",
        "email",
        "email_verify",
        "first_name",
        "last_name",
        "is_staff",
        "car",
    )
    fieldsets = (
        (None, {"fields": ("username", "password")}),
        (
            _("Personal info"),
            {"fields": ("first_name", "last_name", "email", "email_verify")},
        ),
        (_("Car"), {"fields": ("car",)}),
        (
            _("Permissions"),
            {
                "fields": (
                    "is_active",
                    "is_staff",
                    "is_superuser",
                    "groups",
                    "user_permissions",
                ),
            },
        ),
        (_("Important dates"), {"fields": ("last_login", "date_joined")}),
    )


class CarAdmin(admin.ModelAdmin):
    list_display = ("body",)


admin.site.register(Profile, ProfileAdmin)
admin.site.register(Car, CarAdmin)
