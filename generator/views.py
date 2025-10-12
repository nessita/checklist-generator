from django.contrib.auth.decorators import permission_required
from django.shortcuts import get_object_or_404, render
from markdown import markdown

from generator.models import (
    BugFixRelease,
    FeatureRelease,
    PreRelease,
    Release,
    SecurityRelease,
)


def render_checklist(request, instance):
    raw_markdown = instance.render_to_string(request=request)
    markdown_content = markdown(
        raw_markdown,
        output_format="html",
        extensions=[
            "pymdownx.extra",
            "pymdownx.tasklist",
            "pymdownx.superfences",
            "pymdownx.magiclink",
        ],
        extension_configs={
            "pymdownx.tasklist": {
                "custom_checkbox": True,
                "clickable_checkbox": True,
            },
        },
    )
    return render(
        request,
        "generator/checklist_detail.html",
        {
            "instance": instance,
            "markdown": markdown_content,
            "raw_markdown": raw_markdown,
        },
    )


def release_checklist(request, version):
    release = get_object_or_404(Release, version=version)
    if release.is_pre_release:
        checklist_model = PreRelease
    elif release.is_dot_zero:
        checklist_model = FeatureRelease
    else:
        checklist_model = BugFixRelease
    instance = get_object_or_404(checklist_model, release__version=version)
    return render_checklist(request, instance)


@permission_required("generator.view_securityrelease")
def securityrelease_checklist(request, pk):
    instance = get_object_or_404(SecurityRelease, pk=pk)
    return render_checklist(request, instance)
