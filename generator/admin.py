from django.contrib import admin
from django.http import HttpResponse
from django.template import RequestContext
from django.template.loader import render_to_string

from django_better_admin_arrayfield.admin.mixins import DynamicArrayMixin
from django_better_admin_arrayfield.models.fields import ArrayField

from .models import (
    BetaRelease,
    FeatureRelease,
    ReleaseCandidateRelease,
    Releaser,
    SecurityIssue,
    SecurityRelease,
)


def render_checklist(request, queryset):
    assert queryset.count() == 1, "A single item should be selected"
    instance = queryset.get()
    context = instance.__dict__
    if getattr(instance, "get_context_data", None) is not None:
        context.update(instance.get_context_data())
    checklist = render_to_string(instance.checklist_template, context, request=request)
    return HttpResponse(checklist, content_type="text/markdown")


class ReleaserAdmin(admin.ModelAdmin):
    list_display = ["user", "key_id", "key_url"]


class ReleaseAdminMixin:
    list_display = ["version", "when", "releaser", "is_lts"]
    list_filter = ["version"]
    actions = ["render_checklist"]
    readonly_fields = ["blogpost_link"]

    @admin.action(description="Render checklists for selected releases")
    def render_checklist(self, request, queryset):
        return render_checklist(request, queryset)


class PreReleaseAdminMixin(ReleaseAdminMixin):
    list_display = ["feature_release"] + ReleaseAdminMixin.list_display
    list_filter = ["feature_release"] + ReleaseAdminMixin.list_filter


class FeatureReleaseAdmin(ReleaseAdminMixin, admin.ModelAdmin):
    list_display = ReleaseAdminMixin.list_display + ["tagline"]
    list_filter = ["version"]


class BetaReleaseAdmin(PreReleaseAdminMixin, admin.ModelAdmin):
    pass


class ReleaseCandidateReleaseAdmin(PreReleaseAdminMixin, admin.ModelAdmin):
    pass


class SecurityReleaseAdmin(ReleaseAdminMixin, DynamicArrayMixin, admin.ModelAdmin):
    _list_display = ReleaseAdminMixin.list_display.copy()
    _list_display.remove("version")
    list_display = ["versions"] + _list_display
    list_filter = ["versions"]


class SecurityIssueAdmin(admin.ModelAdmin):
    list_display = ["cve_year_number", "summary", "severity"]
    list_filter = ["severity"]
    search_fields = ["cve_year_number", "summary", "description"]


admin.site.register(FeatureRelease, FeatureReleaseAdmin)
admin.site.register(BetaRelease, BetaReleaseAdmin)
admin.site.register(ReleaseCandidateRelease, ReleaseCandidateReleaseAdmin)
admin.site.register(Releaser, ReleaserAdmin)
admin.site.register(SecurityRelease, SecurityReleaseAdmin)
admin.site.register(SecurityIssue, SecurityIssueAdmin)
