{% load generator_extras %}
# Django {{ instance.verbose_version|default:version }} {{ title }} - {{ when|date }}

## Before Release

- [ ] Resolve release blockers
- [ ] Update [forum post]({{ instance.forum_post }}) with any relevant news
- [ ] Draft blog post
  - Headline: `Django {{ instance.verbose_version|default:version }} released`
  - Slug: `{{ slug }}`
  - Format: reStructuredText
  - Summary: `{{ instance.blogpost_summary }}`
  - Body:
```
{% include instance.blogpost_template %}
```

## Release Day ** DOUBLE CHECK THIS LIST **

- [ ] Update manpage
- [ ] Make cosmetic edits to release notes
- [ ] Check [Jenkins](https://djangoci.com) is green for the version(s) you're putting out. You probably shouldn't issue a release until it's green.
- [ ] A release always begins from a release branch, so you should make sure you're on a **stable branch** and up-to-date
  - `git checkout {{ release.stable_branch }} && git pull -v`
- [ ] Local updates of version and trove classifier:
  - Update the version number in `django/__init__.py` for the release.
    {% if instance.previous_status %}- Change `{{ instance.previous_status }}` to `{{ instance.status }}`{% endif %}
  - Ensure the "Development Status" trove classifier in `pyproject.toml` is:
    - `{{ instance.trove_classifier }}`
  - Commit msg: `{{ release.commit_prefix }} Bumped version for {{ instance.verbose_version|default:version }} release.`
  - e.g. https://github.com/django/django/commit/25fec8940b24107e21314ab6616e18ce8dec1c1c
- [ ] Make sure you have an absolutely clean tree by running (use script here)
  - `git clean -dfx`
- [ ] Run release script
  - `do_django_release.py`
- [ ] Execute ALL commands BUT upload to PyPI
  - `gpg --clearsign -u 124304+nessita@users.noreply.github.com --digest-algo SHA256 <path-to-checksums-folder>/Django-{{ version }}.checksum.txt`
  - `scp -i ~/.ssh/dali/id_rsa <path-to-checksums-folder>/Django-{{ version }}.checksum.txt.asc www@origin.djangoproject.com:/home/www/www/media/pgp/Django-{{ version }}.checksum.txt`
  - `scp -i ~/.ssh/dali/id_rsa dist/Django-* www@origin.djangoproject.com:/home/www/www/media/releases/{{ release.feature_version }}`
  - `git tag --sign --message="Tag {{ version }}" {{ version }}`
  - `git tag --verify {{ version }}`
  - `git push --tags`
- [ ] Test the release locally with helper
  - `RELEASE_VERSION={{ version }} test_new_version.sh`
- [ ] Confirm the release with Jenkins
  - https://djangoci.com/job/confirm-release/: `{{ version }}`
- [ ] Push your work: version update(s), including the new tag
  - `git push`
  - `git push --tags`
- [ ] Upload to PyPI
  - `twine upload dist/*`
  - https://pypi.org/project/Django/{{ version }}/
- [ ] Go to the[ Add release page in the admin](https://www.djangoproject.com/admin/releases/release/add/), enter the new release number
  - {{ version }} ({% if not release.is_lts %}non {% endif %}LTS)
  - https://www.djangoproject.com/admin/releases/release/{{ version }}/change/
- [ ] Publish blog post
- [ ] Post the release announcement to the [django-announce](https://docs.djangoproject.com/en/dev/internals/mailing-lists/#django-announce-mailing-list) and in the Django Forum.
  - Subject: `Django {{ instance.verbose_version|default:version }} released`
  - Body:
```
Details are available on the Django project weblog:
{{ instance.blogpost_link }}
```
{% if self.status == "c" %}
- [ ] Post on Forum calling for translations!
  - e.g. https://forum.djangoproject.com/t/django-5-0-string-freeze-is-in-effect-translations-needed/25511
{% endif %}

