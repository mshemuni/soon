from __future__ import annotations

from django.contrib.auth.models import AbstractUser
from django.db import models

from soon_aip.models import random_key


class CustomUser(AbstractUser):
    username = models.CharField(max_length=50, unique=True, verbose_name="Kullanıcı Adı")
    apikey = models.CharField(max_length=36, null=False, blank=False, unique=True, default=random_key,
                              verbose_name="API Anahtarı")
    email = models.EmailField('email address', unique=False, blank=True)
    first_name = models.CharField(max_length=50, null=False, blank=False, unique=False, verbose_name="Ad")
    last_name = models.CharField(max_length=50, null=False, blank=False, unique=False, verbose_name="Soyad")

    REQUIRED_FIELDS = ['email', 'first_name', 'last_name']

    def __str__(self) -> str:
        return f"{self.full_name()}"

    def full_name(self) -> str:
        return f"{self.first_name} {self.last_name}"

    class Meta:
        verbose_name = 'Kullanıcı'
        verbose_name_plural = 'Kullanıcılar'
