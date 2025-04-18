from django.contrib.auth import update_session_auth_hash
from django.http import Http404
from django.shortcuts import render, get_object_or_404, redirect
from django.urls import reverse_lazy
from django.utils.safestring import mark_safe

from tks.utils import check_permission
from tks.views import TKSView
from .forms import PeopleForm, CustomUserPasswordChangeForm
from .models import People, CustomUser


class PeopleView(TKSView):
    def get(self, request):
        people = People.objects.all().exclude(first_name__in=["Hurdacı", "Dış"])
        return render(request, 'people/index.html', {
            "SITE_NAME": self.SITE_NAME,
            "TITLE": "Bireyler",
            "people": people
        })


class PersonView(TKSView):
    def get(self, request, person_id):
        person = get_object_or_404(People, pk=person_id)
        return render(request, 'people/person.html', {
            "SITE_NAME": self.SITE_NAME,
            "TITLE": "Birey",
            "person": person
        })


class PeopleAddView(TKSView):
    def get(self, request):
        check_permission(request, self.SITE_NAME)

        form = PeopleForm()
        return render(request, 'add.html', {
            "SITE_NAME": self.SITE_NAME,
            "TITLE": "Birey Ekle",
            "form": form
        })

    def post(self, request):
        check_permission(request, self.SITE_NAME)

        form = PeopleForm(request.POST)
        if form.is_valid():
            post = form.save(commit=False)
            post.created_by = request.user
            post.save()
            return redirect(reverse_lazy("people"))

        return render(request,
                      'add.html',
                      {
                          "SITE_NAME": self.SITE_NAME,
                          "TITLE": "Birey Ekle",
                          "form": form,
                      }
                      )


class PeopleEditView(TKSView):
    def get(self, request, person_id):
        check_permission(request, self.SITE_NAME)

        person = get_object_or_404(People, pk=person_id)

        if person.first_name in ["Hurdacı", "Dış"]:
            return render(request, 'error.html', {
                "SITE_NAME": self.SITE_NAME,
                "TITLE": "Hata",
                'message': mark_safe(
                    f"<h2>Bu birey düzenlenemez</h2>"
                )
            })

        form = PeopleForm(instance=person)
        return render(request, 'edit.html', {
            "SITE_NAME": self.SITE_NAME,
            "TITLE": "Birey Düzenle",
            'form': form
        })

    def post(self, request, person_id):
        check_permission(request, self.SITE_NAME)

        person = get_object_or_404(People, pk=person_id)

        if person.first_name in ["Hurdacı", "Dış"]:
            return render(request, 'error.html', {
                "SITE_NAME": self.SITE_NAME,
                "TITLE": "Hata",
                'message': mark_safe(
                    f"<h2>Bu birey düzenlenemez</h2>"
                )
            })

        form = PeopleForm(request.POST, instance=person)
        if form.is_valid():
            post = form.save(commit=False)
            post.save()
            return redirect("people")

        return render(request, 'edit.html', {
            "SITE_NAME": self.SITE_NAME,
            "TITLE": "Birey Düzenle",
            'form': form
        })


class PeopleDeleteView(TKSView):
    def get(self, request, person_id):
        check_permission(request, self.SITE_NAME)

        person = get_object_or_404(People, pk=person_id)

        if person.first_name in ["Hurdacı", "Dış"]:
            return render(request, 'error.html', {
                "SITE_NAME": self.SITE_NAME,
                "TITLE": "Hata",
                'message': mark_safe(
                    f"<h2>Bu birey silinemez</h2>"
                )
            })

        return render(request, 'delete.html', {
            "SITE_NAME": self.SITE_NAME,
            "TITLE": "Birey Sil",
            'tobe_deleted': person
        })

    def post(self, request, person_id):
        check_permission(request, self.SITE_NAME)

        person = get_object_or_404(People, pk=person_id)

        if person.first_name in ["Hurdacı", "Dış"]:
            return render(request, 'error.html', {
                "SITE_NAME": self.SITE_NAME,
                "TITLE": "Hata",
                'message': mark_safe(
                    f"<h2>Bu birey silinemez</h2>"
                )
            })

        person.delete()

        return redirect("people")


class UserPasswrdEditView(TKSView):
    def get(self, request):
        user = get_object_or_404(CustomUser, id=request.user.pk)
        form = CustomUserPasswordChangeForm(user=user)
        return render(request,
                      'edit.html',
                      {
                          "SITE_NAME": self.SITE_NAME,
                          "TITLE": "Kullanıcı Şifre Değiştir",
                          "form": form,
                      })

    def post(self, request):
        user = get_object_or_404(CustomUser, id=request.user.pk)
        form = CustomUserPasswordChangeForm(user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)

            return redirect("home")

        return render(request,
                      'edit.html',
                      {
                          "SITE_NAME": self.SITE_NAME,
                          "TITLE": "Kullanıcı Şifre Değiştir",
                          "form": form,
                      })
