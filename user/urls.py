from django.contrib.auth.decorators import login_required
from django.urls import path, include
from .views import PeopleView, PeopleAddView, PeopleEditView, PersonView, PeopleDeleteView, UserPasswrdEditView

urlpatterns = [
    path("", login_required(PeopleView.as_view()), name="people"),
    path("<int:person_id>", login_required(PersonView.as_view()), name="people_person"),
    path("add", login_required(PeopleAddView.as_view()), name="people_add"),
    path("edit/<int:person_id>", login_required(PeopleEditView.as_view()), name="people_edit"),
    path("delete/<int:person_id>", login_required(PeopleDeleteView.as_view()), name="people_delete"),
    path("profile/edit/password", UserPasswrdEditView.as_view(), name="profile_password_edit"),

]
