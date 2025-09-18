from django.contrib.auth.forms import UserChangeForm, PasswordChangeForm

from django import forms
from .models import CustomUser, People


class UserUpdateForm(UserChangeForm):
    class Meta:
        model = CustomUser
        fields = ['username', 'email', 'first_name', 'last_name']


class PeopleForm(forms.ModelForm):
    class Meta:
        auto_id = 'person_%s'
        model = People
        fields = ('first_name', 'last_name', 'unit', 'email', 'phone')


class CustomUserPasswordChangeForm(PasswordChangeForm):
    class Meta:
        model = CustomUser
        fields = ("old_password", "new_password1", "new_password2")
        widgets = {
            'old_password': forms.PasswordInput(attrs={
                'class': "form-control",
            }),
            'new_password1': forms.PasswordInput(attrs={
                'class': "form-control",
            }),
            'new_password2': forms.PasswordInput(attrs={
                'class': "form-control",
            })
        }

    def __init__(self, *args, **kwargs):
        super(CustomUserPasswordChangeForm, self).__init__(*args, **kwargs)
        self.fields['old_password'].widget.attrs['class'] = 'form-control'
        self.fields['new_password1'].widget.attrs['class'] = 'form-control'
        self.fields['new_password2'].widget.attrs['class'] = 'form-control'
