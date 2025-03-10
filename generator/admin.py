from django.contrib import admin
from django.http import HttpResponse
from django.template import RequestContext
from django.template.loader import render_to_string

from django_better_admin_arrayfield.admin.mixins import DynamicArrayMixin
from django_better_admin_arrayfield.models.fields import ArrayField

from .models import (
    FeatureRelease,
    PreRelease,
    Release,
    Releaser,
    SecurityIssue,
    SecurityIssueReleasesThrough,
    SecurityRelease,
)


def render_checklist(request, queryset):
    assert queryset.count() == 1, "A single item should be selected"
    instance = queryset.get()
    context = {"release": instance, "title": instance.__class__.__name__, **instance.__dict__}
    if getattr(instance, "get_context_data", None) is not None:
        context.update(instance.get_context_data())
    checklist = render_to_string(instance.checklist_template, context, request=request)
    return HttpResponse(checklist, content_type="text/markdown")


class ReleaseAdmin(admin.ModelAdmin):
    list_display = ["version", "date", "is_lts"]
    ordering = ["-version"]


class ReleaserAdmin(admin.ModelAdmin):
    list_display = ["user", "key_id", "key_url"]


class ReleaseEventAdminMixin:
    list_display = ["version", "when", "releaser"]
    list_filter = ["releaser"]
    actions = ["render_checklist"]
    readonly_fields = ["blogpost_link"]

    def queryset(self, request):
        return super().get_queryset(request).select_related("release")

    @admin.action(description="Render checklists for selected releases")
    def render_checklist(self, request, queryset):
        return render_checklist(request, queryset)


class PreReleaseAdmin(ReleaseEventAdminMixin, admin.ModelAdmin):
    list_display = ["feature_release"] + ReleaseEventAdminMixin.list_display
    list_filter = ["feature_release"] + ReleaseEventAdminMixin.list_filter


class FeatureReleaseAdmin(ReleaseEventAdminMixin, admin.ModelAdmin):
    list_display = ReleaseEventAdminMixin.list_display + ["tagline"]


class SecurityReleaseAdmin(ReleaseEventAdminMixin, DynamicArrayMixin, admin.ModelAdmin):
    list_display = ["versions", "when", "releaser"]
    search_fields = ["affected_branches"]
    ordering = ["-when"]
    readonly_fields = ["hashes_by_versions"]



class SecurityIssueAdmin(admin.ModelAdmin):
    list_display = ["cve_year_number", "summary", "severity", "commit_hash_main"]
    list_filter = ["severity"]
    search_fields = ["cve_year_number", "summary", "description", "commit_hash_main"]
    ordering = ["-cve_year_number"]
    readonly_fields = ["hashes_by_branch"]


class SecurityIssueReleasesThroughAdmin(admin.ModelAdmin):
    list_display = ["securityissue__cve_year_number", "release__version", "commit_hash"]
    list_filter = ["release__version"]
    search_fields = [
        "securityissue__cve_year_number",
        "release__version",
        "commit_hash",
    ]
    ordering = ["-securityissue__cve_year_number", "release__version"]


admin.site.register(FeatureRelease, FeatureReleaseAdmin)
admin.site.register(PreRelease, PreReleaseAdmin)
admin.site.register(Release, ReleaseAdmin)
admin.site.register(Releaser, ReleaserAdmin)
admin.site.register(SecurityRelease, SecurityReleaseAdmin)
admin.site.register(SecurityIssue, SecurityIssueAdmin)
admin.site.register(SecurityIssueReleasesThrough, SecurityIssueReleasesThroughAdmin)
