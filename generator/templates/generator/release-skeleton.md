{% load generator_extras %}
# Django {{ release.version_verbose }} {{ title }} - {{ when|date }}

## Before Release

- [ ] Resolve release blockers
{% if instance.forum_post %}- [ ] Update [forum post]({{ instance.forum_post }}) with any relevant news{% endif %}
{% include 'generator/_write_blogpost.md' with final_version=release.feature_version %}
{% if release.is_dot_zero %}
- [ ] Create a new branch from the current stable branch in the [django-docs-translations repository](https://github.com/django/django-docs-translations):
  - `git checkout -b {{ release.stable_branch }} origin/{{ instance.eom_release.stable_branch }}`
  - `git push origin {{ release.stable_branch }}:{{ release.stable_branch }}`
{% elif release.status == "a" %}
## Feature Freeze Day
{% include 'generator/_feature_freeze.md' with final_version=release.feature_version %}
{% endif %}

## Release Day

- [ ] Polish and  make cosmetic edits to release notes on `main` and backport
  {% if not release.is_pre_release %}- Remove the `Expected` prefix and update the release date if necessary{% endif %}
  {% if release.is_dot_zero %}- Remove the `UNDER DEVELOPMENT` header at the top of the release notes:
  - e.g. https://github.com/django/django/commit/1994a2643881a9e3f9fa8d3e0794c1a9933a1831{% endif %}
- [ ] Check [Jenkins](https://djangoci.com) is green for the version(s) you're putting out.
      You probably shouldn't issue a release until it's green.
- [ ] A release always begins from a release branch, so you should make sure you're on the up-to-date **stable branch**
  - `git checkout {{ release.stable_branch }} && git pull -v`
{% if not release.is_pre_release %}{% include 'generator/_update_man_page.md' %}{% endif %}

### Build artifacts
{% include 'generator/_build_release_binaries.md' %}

### Publish artifacts

{% include 'generator/_make_release_public.md' %}

### Final tasks

{% if not release.is_pre_release %}{% include "generator/_stub_release_notes.md" %}{% endif %}
{% include "generator/_push_changes_and_announce.md" %}
{% if release.status == "a" %}
- [ ] Add the feature release in [Trac's versions list](https://code.djangoproject.com/admin/ticket/versions).
{% endif %}
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
- [ ] Update the `default_version` setting in the code.djangoproject.com's `trac.ini` file
  - e.g. https://github.com/django/code.djangoproject.com/pull/268
{% elif release.is_pre_release %}
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
