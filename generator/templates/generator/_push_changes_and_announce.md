- [ ] Push changes to relevant branches:
{% if not instance.is_pre_release %}
    - `git checkout main && git log`
    - `git push -v`{% endif %}
{% for release in instance.affected_releases %}
    - `git checkout {{ release.stable_branch }} && git log`
    - `git push -v`
{% endfor %}

- [ ] Push all the new tags at once
    - `git push --tags`

- [ ] Publish blogpost

- [ ] Email to `django-announce@googlegroups.com`
    - Title: `{{ instance.blogpost_title }}`
    - Body with short notice and link to blogpost for more details:
```
Details are available on the Django project weblog:
{{ instance.blogpost_link }}
```

- [ ] Post in forum https://forum.djangoproject.com/t/django-release-announcements/655/
    - e.g. https://forum.djangoproject.com/t/django-release-announcements/655/71
```
## {{ instance.blogpost_title }}

:mega: Announcement: {{ instance.blogpost_link }}

:tada: Release notes:
{% if instance.is_pre_release %}
 * https://docs.djangoproject.com/en/dev/releases/{{ instance.feature_release.version }}
{% else %}{% for version in instance.versions %}
 * https://docs.djangoproject.com/en/stable/releases/{{ version }}{% endfor %}{% endif %}
```
