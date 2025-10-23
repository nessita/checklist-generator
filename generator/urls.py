from django.urls import path

from generator import views

app_name = "generator"

urlpatterns = [
    path(
        "release/<str:version>/",
        views.release_checklist,
        name="release_checklist",
    ),
    path(
        "security/release/<int:pk>/",
        views.securityrelease_checklist,
        name="securityrelease_checklist",
    ),
    path("security/issue/<str:cve_id>/", views.cve_json_record, name="cve_json_record"),
]
