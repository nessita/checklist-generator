{% load generator_extras %}
# Django Security Release: {{ versions|enumerate_items }} ({{ when }})
{% with cves_length=cves|length %}
## 14 days before

- [ ] Create issues in https://github.com/django/django-security/issues/
  - Add labels for affected versions
  - Add label for severity
  - e.g. https://github.com/django/django-security/issues/362
- [ ] Prepare fixes targeting main, get reviews, include release notes
- [ ] Submit a CVE Request https://cveform.mitre.org for all issues
  - Select a request type: `Report Vulnerability/Request CVE ID`
  - Enter your e-mail address: `security@djangoproject.com`
  - Enter a PGP Key (to encrypt): *leave blank*
  - Number of vulnerabilities reported or IDs requested (1-10) info: `{{ cves_length }}`
  - I have verified that this vulnerability is not in a CNA-covered product: `Yes`
  - I have verified that the vulnerability has not already been assigned a CVE ID: `Yes`
  {% for cve in cves %}
  - For issue **{{ cve.summary }}**:
    - Vulnerability type info: `{{ cve.cve_type }}`
    {% if cve.other_type %}
    - Other vulnerability type info: `{{ cve.other_type }}`
    {% endif %}
    - Vendor of the product(s) info: `djangoproject`
    - Affected product(s)/code base (SPLIT in product and version (X before Y) in rows!):
      ```{% for version in versions %}
      [row 1] Django
      [row 2] {{ version|format_version_for_cve }}
      {% if not forloop.last %}---------- Click [+] Add ----------{% endif %}{% endfor %}```
    - Has vendor confirmed or acknowledged the vulnerability? `Yes`
    - Attack type info: `{{ cve.attack_type }}`
    - Impact info: `{{ cve.impact }}`
    - Affected component(s): *leave blank*
    - Attack vector(s): *leave blank*
    - Suggested description of the vulnerability for use in the CVE info:
      ```
      An issue was discovered in {{ versions|format_versions_for_cves }}.
      {{ cve.description }}
      ```
    - Discoverer(s)/Credits info: `{{ cve.reporter }}`
    - Reference(s) info:
      ```
      https://groups.google.com/g/django-announce
      https://docs.djangoproject.com/en/dev/releases/security/
      ```
  {% endfor %}
- [ ] Write blogpost draft
  - Include REPORTER and severity!
  - e.g. https://www.djangoproject.com/admin/blog/entry/706/change/
  - Title: `Django security releases issued: {{ versions|enumerate_items }}`
  - Slug: `security-releases`
  - Summary: `Django {{ versions|enumerate_items }} fix {% if cves_length == 1 %}one security issue{% else %}{{ cves_length }} security issues{% endif %}.`
  - Body:
```
{% include 'generator/release_security_blogpost.rst' %}
```

## 10 days before

- [ ] Prepare patches targeting releases {{ versions|enumerate_items }}, and main
  - `git format-patch HEAD~{{ cves_length }}`
  - e.g. https://github.com/django/django-security/pull/375

## One Week before

- [ ] Sent prenotification email
  - `Notice of upcoming Django security releases ({{ versions|enumerate_items }})`
  - Use blogpost draft, create a new text file with content.
    - Reference: https://github.com/django/django-security/wiki/Security-prenotification-email-template
  - GPG sign that new file: `gpg --clearsign --digest-algo SHA256 prenotification-email.txt`
  - Send signed content to a given list of special users.
    - Attach patches.
    - USE BCC!: https://github.com/django/django-security/wiki/Security-Release-Prenotification-Email-List
- [ ] Post announcement in mailing list (without details)
    ```
    Django versions {{ versions|enumerate_items }} will be released on
    {{ when.date|date:"l, F j" }} around {{ when.time|date:"H:i" }} UTC.
    {% if cves_length == 1 %}
    They will fix one security defect with severity "{{ cves.0.severity }}".
    {% else %}
    They will fix {{ cves_length }} security defects with severities: {{ cves|enumerate_cves:"severity" }}.
    {% endif %}
    For details of severity levels, see:
    https://docs.djangoproject.com/en/dev/internals/security/#how-django-discloses-security-issues
    ```

## Release Day

- [ ] Update security report and update patches for main and stable branches
- [ ] Empty push to private GH so actions are (re)run
- [ ] Regenerate patches against latest revno in each branch
  - `git format-patch HEAD~{{ cves_length }}`

### For each binary release -- DO NOT PUSH ANYTHING YET
{% for version in versions %}
#### For {{ version }}
{% include 'generator/_make_release_public.md' %}
{% endfor %}

### For main -- DO NOT PUSH ANYTHING YET
- [ ] Start release notes for a new version, in the main branch, only for the latest stable branch!
  {% with next_version=versions.0|next_version %}
  - Edit `docs/releases/index.txt`
  - Create empty file for release at `docs/releases/{{ next_version }}.txt`
      - Add basic content:

        ```
        ==========================
        Django {{ next_version }} release notes
        ==========================

        *Expected {{ when|next_release_date|date:"F j, Y" }}*

        Django {{ next_version }} fixes several bugs in {{ versions.0 }}.

        Bugfixes
        ========

        * ...
        ```
  - Confirm docs works
      - `make html`
  - Commit
      - `Added stub release notes for {{ next_version }}.`
  - Backport to latest stable branch!
      -  `backport.sh {HASH}`
- [ ] Add security patches entry to archive, in main and backport
  - Edit `docs/releases/security.txt`
      - Need hashes
```
{% include 'generator/release_security_archive.rst' %}
```
  - `make html`
  - `git commit -m 'Added {{ cves|enumerate_cves }} to security archive.'`
  - Check links from local docs
      - `firefox _build/html/releases/security.html`
  - Backport to all branches!!!
    {% for version in versions %}
    - `git checkout {{ version|stable_branch }} && git pull -v && backport.sh {HASH}`
    {% endfor %}
  {% endwith %}

### Final tasks

- [ ] Push changes to `main` and any stable branch, including pre-releases:
  - `git checkout main && git log && git push -v`
{% for version in versions %}
  - `git checkout {{ version|stable_branch }} && git log && git push -v`
{% endfor %}
- [ ] Push all the new tags at once
  - `git push --tags`
- [ ] Publish blogpost draft
  - Include hashes!
- [ ] Email to `django-announce@googlegroups.com, django-developers@googlegroups.com, django-users@googlegroups.com`
  - Title: `Django security releases issued: {{ versions|enumerate_items }}`
  - Body with short notice and link to blogpost for more details
```
Details are available on the Django project weblog:
{{ release.blogpost_link }}
```

- [ ] Post in forum https://forum.djangoproject.com/t/django-release-announcements/655/
  - e.g. https://forum.djangoproject.com/t/django-release-announcements/655/71
```
## Django security releases issued: {{ versions|enumerate_items }}

:mega: Announcement:
{{ release.blogpost_link }}

:tada: Release notes:{% for version in versions %}
 * https://docs.djangoproject.com/en/dev/releases/{{ version }}{% endfor %}
```
- [ ] Edit IRC topic
- [ ] Send email to CVE people so the CVE entry is public (is private until now)
  - To: `oss-security@lists.openwall.com`
  - Cc: `security@djangoproject.com`
  - Subject: `Django {{ cves|enumerate_cves }}`
  - Body includes link to blog and blogpost text
- [ ] Close PRs in security repo linking hashes
  {% regroup hashes_by_versions|dictsortreversed:"branch" by branch as items %}
  {% for item in items %}
#### For {{ item.grouper }}
```{% for i in item.list %}
* Fix for {{ i.cve }} merged in {{ i.hash }}.{% endfor %}
```
  {% endfor %}
- [ ] Close issues in security repo linking hashes
  - e.g. https://github.com/django/django-security/issues/376
  {% regroup hashes_by_versions|dictsort:"cve" by cve as items %}
  {% for item in items %}
#### For {{ item.grouper }}
```
Fixed:{% for i in item.list|dictsortreversed:'branch' %}
* On the [{{ i.branch }} branch](https://github.com/django/django/commit/{{ i.hash }}){% endfor %}
```
  {% endfor %}
- [ ] Remove branches
{% endwith %}
