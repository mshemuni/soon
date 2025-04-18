"""
URL configuration for soon_aip project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from ninja import NinjaAPI
from ninja.security import APIKeyHeader

from soon_aip.api import router as gpo_router
from soon_aip.views import HomeView

from user.models import CustomUser


class ApiKey(APIKeyHeader):
    param_name = "X-API-Key"

    def authenticate(self, request, key):
        try:
            cu = CustomUser.objects.get(apikey=key)
            return cu
        except CustomUser.DoesNotExist:
            pass


api = NinjaAPI(
    title="Soon API",
    version="0.0.1 Beta",
    description=f"This is an API to manage GPOs on a samba-ad-dc. <a href='/'>Home</a>",
    auth=ApiKey(),
    # auth=None
)

# <br>`c16658b5-16c2-403b-9403-3b1faf94da86`

api.add_router("gpo", gpo_router)

urlpatterns = [
    path('admin/', admin.site.urls),
    path("", HomeView.as_view(), name="home"),
    path("api/v1/", api.urls, name="api")
]
