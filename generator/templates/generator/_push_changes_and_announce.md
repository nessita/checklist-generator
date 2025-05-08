- [ ] Push changes to `main` and any stable branch, including pre-releases:
  - `git checkout main && git log && git push -v`
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

:tada: Release notes:{% for version in instance.versions %}
 * https://docs.djangoproject.com/en/stable/releases/{{ version }}{% endfor %}
```
