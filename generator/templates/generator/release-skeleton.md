{% load generator_extras %}
# Django {{ instance.verbose_version }} {{ title }} - {{ when|date }}

## Before Release

- [ ] Resolve release blockers
- [ ] Update [forum post]({{ instance.forum_post }}) with any relevant news
- [ ] Draft blog post
  - Headline: `{{ instance.blogpost_title }}`
  - Slug: `{{ slug }}`
  - Format: reStructuredText
  - Summary: `{{ instance.blogpost_summary }}`
  - Body:
```
{% include instance.blogpost_template with final_version=release.feature_version %}
```
{% if release.is_dot_zero %}
- [ ] Create a new branch from the current stable branch in the [django-docs-translations repository](https://github.com/django/django-docs-translations):
  - `git checkout -b {{ release.stable_branch }} origin/{{ instance.eom_release.stable_branch }}`
  - `git push origin {{ release.stable_branch }}:{{ release.stable_branch }}`
{% endif %}

## Release Day

- [ ] Polish and if necessary make cosmetic edits to release notes on `main` and backport{% if release.is_dot_zero %}:
  - Remove the `UNDER DEVELOPMENT` header at the top of the release notes
  - Remove the `Expected` prefix and update the release date if necessary
  - e.g. https://github.com/django/django/commit/1994a2643881a9e3f9fa8d3e0794c1a9933a1831{% endif %}
- [ ] Check [Jenkins](https://djangoci.com) is green for the version(s) you're putting out.
      You probably shouldn't issue a release until it's green.
- [ ] A release always begins from a release branch, so you should make sure you're on the up-to-date **stable branch**
  - `git checkout {{ release.stable_branch }} && git pull -v`
- [ ] Update manpage
  - `cd docs`
  - `make man`
  - `man _build/man/django-admin.1`  # do a quick sanity check
  - `cp _build/man/django-admin.1 man/django-admin.1`
  - e.g. https://github.com/django/django/commit/34bc3a3f88a5f9829df91afae9ee9bae5dae310a

### Build artifacts
{% include 'generator/_build_release_binaries.md' %}

### Publish artifacts

{% include 'generator/_make_release_public.md' %}

### Final tasks

{% if release.status == "f" %}{% include "generator/_stub_release_notes.md" %}{% endif %}
{% include "generator/_push_changes_and_announce.md" %}
{% if release.is_dot_zero %}
- [ ] Update the metadata for the docs in https://www.djangoproject.com/admin/docs/documentrelease/:
  - Set `is_default` flag to `True` in the `DocumentRelease` English entry for this release (this will automatically flip all the others to `False`).
  - Create new `DocumentRelease` objects for each language that has an entry for the previous release.
- [ ] Update djangoproject.com's [robots.docs.txt](https://github.com/django/djangoproject.com/blob/main/djangoproject/static/robots.docs.txt) file:
  - This is the result from running in the [django-docs-translations repository](https://github.com/django/django-docs-translations)
  - `git checkout {{ release.stable_branch }} && git pull -v`
  - `python manage_translations.py robots_txt`
  - e.g. https://github.com/django/djangoproject.com/pull/1445
- [ ] Update the current stable branch and remove the pre-release branch in the
      [Django release process](https://code.djangoproject.com/#Djangoreleaseprocess) on Trac.
- [ ] Update the download page on djangoproject.com.
  - e.g. https://github.com/django/django/commit/d2b1ec551567c208abfdd21b27ff6d08ae1a6371.
{% elif release.status != "f" %}
- [ ] Update the translation catalogs:
  - Make a new branch from the recently released stable branch:
    - `git checkout {{ release.stable_branch }} && git pull -v`
    - `git checkout -b update-translations-catalog-{{ release.feature_version }}.x`
  - Ensure that the release's dedicated virtual environment is enabled and run the following:
      - `cd django`
      - `django-admin makemessages -l en --domain=djangojs --domain=django`
  - Review the diff before pushing and avoid committing changes to the `.po` files without any new translations.
  - e.g. https://github.com/django/django/commit/d2b1ec551567c208abfdd21b27ff6d08ae1a6371.
  - Make a pull request against the corresponding stable branch and merge once approved.
  - Forward port the updated source translations to the `main` branch.
  - e.g. https://github.com/django/django/commit/aed303aff57ac990894b6354af001b0e8ea55f71.
{% endif %}
{% if release.status == "c" %}
- [ ] Post on Forum calling for translations!
  - e.g. https://forum.djangoproject.com/t/django-5-0-string-freeze-is-in-effect-translations-needed/25511
{% endif %}
