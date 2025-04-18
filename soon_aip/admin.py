from django.contrib import admin


class SoonAdmin(admin.ModelAdmin):
    def save_model(self, request, instance, form, change) -> None:
        user = request.user
        instance = form.save(commit=False)
        if not change:
            instance.created_by = user

        instance.save()
        form.save_m2m()