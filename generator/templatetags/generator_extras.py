from datetime import timedelta

from django import template


register = template.Library()


@register.filter
def split_patch_version(version):
    return version.rsplit(".", 1)


@register.filter
def major_minor_version(version):
    if version.count(".") > 1:
        result = split_patch_version(version)[0]
    else:
        result = version
    return result


@register.filter
def patch_version(version):
    return split_patch_version(version)[-1]


@register.filter
def series(version):
    return f"{major_minor_version(version)}.x"


@register.filter
def stable_branch(version):
    return f"stable/{series(version)}"


@register.filter
def next_version(version):
    version, patch = split_patch_version(version)
    return f"{version}.{int(patch)+1}"


@register.filter
def next_release_date(value):
    return value + timedelta(days=30)


@register.filter
def enumerate_items(items, item_formatter=None):
    if item_formatter is not None:
        items = [item_formatter(item) for item in items]
    *rest, last = items
    if not rest:
        return last

    last_joiner = ", and " if len(rest) > 2 else " and "  # Oxford comma
    return last_joiner.join((", ".join(rest), last))


@register.filter
def enumerate_cves(cves, field="cve_year_number"):
    return enumerate_items([getattr(cve, field) for cve in cves])


@register.filter
def format_version_for_cve(version):
    return f"{major_minor_version(version)} before {version}"


@register.filter
def format_versions_for_cves(versions):
    return enumerate_items(versions, item_formatter=format_version_for_cve)


@register.filter
def format_version_for_blogpost(version):
    return (
        f"`Django {version} "
        f"<https://docs.djangoproject.com/en/dev/releases/{version}/>`_"
    )


@register.filter
def format_versions_for_blogpost(versions):
    return enumerate_items(versions, item_formatter=format_version_for_blogpost)


@register.filter
def rst_underline_for_headline(headline, headline_char="="):
    headline_underline = headline_char * len(headline)
    return f"{headline}\n{headline_underline}"
