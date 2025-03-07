{% load generator_extras %}

# Django {{ release.final_version }} {{ title }} - {{ when|date }}

## Before Release

- [ ] Resolve release blockers
- [ ] Update [forum post]({{ feature_release.forum_post }}) with any relevant news
- [ ] Draft blog post
  - Headline: `Django {{ release.verbose_version }} released`
  - Slug: `{{ release.slug }}`
  - Format: reStructuredText
  - Summary: `Today Django {{ release.verbose_version }}, a preview/testing package for the upcoming Django {{ release.final_version }} release, is available.`
  - Body:
```
{% include 'generator/release_rc_blogpost.rst' %}
```


## Release Day

- [ ] Update manpage
- [ ] Make cosmetic edits to release notes
- [ ] Check [Jenkins](https://djangoci.com) is green for the version(s) you're putting out. You probably shouldn't issue a release until it's green.
- [ ] A release always begins from a release branch, so you should make sure you're on a **stable branch** and up-to-date
  - `git checkout {{ release.final_version|stable_branch }} && git pull -v`
- [ ] Local update of version:
  - Update the version number in `django/__init__.py` for the release, change `beta` by `rc`
  - DO NOT update the "Development Status" trove classifier in `pyproject.toml` (it will continue to say `Development Status :: 4 - Beta`.
  - Commit msg: `[{{ release.final_version }}.x] Bumped version for {{ release.verbose_version }}.`
  - e.g. https://github.com/django/django/commit/25fec8940b24107e21314ab6616e18ce8dec1c1c
- [ ] Make sure you have an absolutely clean tree by running (use script here)
  - `git clean -dfx`
- [ ] Run release script
  - `do_django_release.py`
- [ ] Execute ALL commands BUT upload to PyPI
  - `gpg --clearsign -u 124304+nessita@users.noreply.github.com --digest-algo SHA256 <path-to-checksums-folder>/Django-{{ release.version }}.checksum.txt`
  - `scp -i ~/.ssh/dali/id_rsa <path-to-checksums-folder>/Django-{{ release.version }}.checksum.txt.asc www@origin.djangoproject.com:/home/www/www/media/pgp/Django-{{ release.version }}.checksum.txt`
  - `scp -i ~/.ssh/dali/id_rsa dist/Django-* www@origin.djangoproject.com:/home/www/www/media/releases/{{ release.final_version }}`
  - `git tag --sign --message="Tag {{ release.version }}" {{ release.version }}`
  - `git tag --verify {{ release.version }}`
  - `git push --tags`
- [ ] Test the release locally with helper
  - `RELEASE_VERSION={{ release.version }} test_new_version.sh`
- [ ] Confirm the release with Jenkins
  - https://djangoci.com/job/confirm-release/: `{{ release.version }}`
- [ ] Push your work: version update(s), including the new tag
  - `git push`
  - `git push --tags`
- [ ] Upload to PyPI
  - `twine upload dist/*`
  - https://pypi.org/project/Django/{{ release.version }}/
- [ ] Go to the[ Add release page in the admin](https://www.djangoproject.com/admin/releases/release/add/), enter the new release number
  - {{ release.version }} ({% if not feature_release.is_lts %}non {% endif %}LTS)
  - https://www.djangoproject.com/admin/releases/release/{{ release.version }}/change/
- [ ] Publish blog post
- [ ] Post the release announcement to the [django-announce](https://docs.djangoproject.com/en/dev/internals/mailing-lists/#django-announce-mailing-list) and to the Django Forum.
  - Subject: `Django {{ release.verbose_version }} released`
  - Body:
```
Details are available on the Django project weblog:
{{ release.blogpost_link }}
```
- [ ] Post on Forum calling for translations!
  - e.g. https://forum.djangoproject.com/t/django-5-0-string-freeze-is-in-effect-translations-needed/25511
