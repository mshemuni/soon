from django.views import View
from django.shortcuts import render

from soon_aip import settings

class TKSView(View):
    SITE_NAME = settings.SITE_HEADER


class HomeView(TKSView):
    def get(self, request):
        return render(request, 'index.html', {
            "SITE_NAME": self.SITE_NAME,
            "TITLE": "Home",
        })