from soon_aip.admin import SoonAdmin


from django.contrib import admin

from user.models import CustomUser


@admin.register(CustomUser)
class CustomUserAdmin(SoonAdmin):
    readonly_fields = ["apikey"]

    list_display = ('full_name', 'username', 'email', 'is_staff', 'apikey')
    fieldsets = [
        (
            "System",
            {
                "fields": ["apikey", "username", "is_active", "is_staff", "is_superuser"],
            },
        ),
        (
            "Personal",
            {
                "fields": ["first_name", "last_name"],
            },
        ),
        (
            "Contact",
            {
                "fields": ["email"],
            },
        ),
    ]

