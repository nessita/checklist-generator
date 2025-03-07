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
    Release,
    Releaser,
    SecurityIssue,
    SecurityIssueReleasesThrough,
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


class ReleaseAdmin(admin.ModelAdmin):
    list_display = ["version", "date", "is_lts"]


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


class PreReleaseAdminMixin(ReleaseEventAdminMixin, admin.ModelAdmin):
    list_display = ["feature_release"] + ReleaseEventAdminMixin.list_display
    list_filter = ["feature_release"] + ReleaseEventAdminMixin.list_filter


class FeatureReleaseAdmin(ReleaseEventAdminMixin, admin.ModelAdmin):
    list_display = ReleaseEventAdminMixin.list_display + ["tagline"]


class SecurityReleaseAdmin(ReleaseEventAdminMixin, DynamicArrayMixin, admin.ModelAdmin):
    list_display = ["versions", "newversions", "newaffected_branches", "when", "releaser"]


class BetaReleaseAdmin(PreReleaseAdminMixin, admin.ModelAdmin):
    pass


class ReleaseCandidateReleaseAdmin(PreReleaseAdminMixin, admin.ModelAdmin):
    pass


class SecurityIssueAdmin(admin.ModelAdmin):
    list_display = ["cve_year_number", "summary", "severity", "commit_hash_main"]
    list_filter = ["severity"]
    search_fields = ["cve_year_number", "summary", "description", "commit_hash_main"]


class SecurityIssueReleasesThroughAdmin(admin.ModelAdmin):
    list_display = ["securityissue__cve_year_number", "release__version", "commit_hash"]
    list_filter = ["release__version"]
    search_fields = ["securityissue__cve_year_number", "release__version", "commit_hash"]


admin.site.register(FeatureRelease, FeatureReleaseAdmin)
admin.site.register(BetaRelease, BetaReleaseAdmin)
admin.site.register(ReleaseCandidateRelease, ReleaseCandidateReleaseAdmin)
admin.site.register(Release, ReleaseAdmin)
admin.site.register(Releaser, ReleaserAdmin)
admin.site.register(SecurityRelease, SecurityReleaseAdmin)
admin.site.register(SecurityIssue, SecurityIssueAdmin)
admin.site.register(SecurityIssueReleasesThrough, SecurityIssueReleasesThroughAdmin)
