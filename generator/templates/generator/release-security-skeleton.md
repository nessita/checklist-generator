{% load generator_extras %}
{% with cves=instance.cves versions=instance.versions cves_length=instance.cves|length %}
# Django Security Release: {{ versions|enumerate_items }} ({{ when }})

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
  {% for cve in cves %}{% with releases=cve.releases.all %}
  - For issue **{{ cve.summary }}**:
    - Vulnerability type info: `{{ cve.cve_type }}`
    {% if cve.other_type %}
    - Other vulnerability type info: `{{ cve.other_type }}`
    {% endif %}
    - Vendor of the product(s) info: `djangoproject`
    - Affected product(s)/code base (SPLIT in product and version (X before Y) in rows!):
      ```{% for release in releases %}{% if not release.is_pre_release %}
      [row 1] Django
      [row 2] {{ release|format_release_for_cve }}
      {% if not forloop.last %}---------- Click [+] Add ----------{% endif %}{% endif %}
      {% endfor %}```
    - Has vendor confirmed or acknowledged the vulnerability? `Yes`
    - Attack type info: `{{ cve.attack_type }}`
    - Impact info: `{{ cve.impact }}`
    - Affected component(s): *leave blank*
    - Attack vector(s): *leave blank*
    - Suggested description of the vulnerability for use in the CVE info:
      ```
      An issue was discovered in {{ releases|format_releases_for_cves }}.
      {{ cve.description }}
      ```
    - Discoverer(s)/Credits info: `{{ cve.reporter }}`
    - Reference(s) info:
      ```
      https://groups.google.com/g/django-announce
      https://docs.djangoproject.com/en/dev/releases/security/
      ```
  {% endwith %}{% endfor %}
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

- [ ] Prepare patches targeting {{ instance.affected_branches|enumerate_items }}
  - `git format-patch HEAD~{{ cves_length }}`
  - e.g. https://github.com/django/django-security/pull/375

## One Week before

- [ ] Sent prenotification email
  - `Notice of upcoming Django security releases ({{ versions|enumerate_items }})`
  - Create a new text file with content similar to this (use CVE parts from the blogpost draft):
    - Reference: https://github.com/django/django-security/wiki/Security-prenotification-email-template
  - GPG sign that new file: `gpg --clearsign --digest-algo SHA256 prenotification-email.txt`
  - Send an email with body using the signed content to a given list of special users:
    - Attach patches.
    - USE BCC!: https://github.com/django/django-security/wiki/Security-Release-Prenotification-Email-List
- [ ] Post announcement in mailing list (without details in django-announce):
    ```
    Django versions {{ versions|enumerate_items }} will be released on
    {{ instance.when.date|date:"l, F j" }} around {{ instance.when.time|date:"H:i" }} UTC.
    {% if cves_length == 1 %}
    They will fix one security defect with severity "{{ cves.0.severity }}".
    {% else %}
    They will fix {{ cves_length }} security defects with severities: {{ cves|enumerate_cves:"severity" }}.
    {% endif %}
    For details of severity levels, see:
    https://docs.djangoproject.com/en/dev/internals/security/#security-issue-severity-levels
    ```

## Release Day

- [ ] Update security report and update patches for main and stable branches
- [ ] Empty push to private GH so actions are (re)run
- [ ] Regenerate patches against latest revno in each branch
  - `git format-patch HEAD~{{ cves_length }}`

### Phase 0: apply patches and build binaries -- DO NOT PUSH NOR PUBLISH ANYTHING YET

#### For `main`
- [ ] Switch to the main branch and update it:
  - `git checkout main && git pull -v`
- [ ] Apply patch
  - `git am path/to/patch/for/main`
{% for release in instance.affected_releases %}
#### For {{ release.version }}{% if release.is_pre_release %} (at pre-release {{ release.get_status_display }} status)
- [ ] Switch to the {{ release.feature_version }} branch and update it:
  - `git checkout {{ release.stable_branch }} && git pull -v`
- [ ] Apply patch
  - `git am path/to/patch/for/{{ release.version }}`
{% else %}{% include 'generator/_build_release_binaries.md' %}{% endif %}
{% endfor %}

### Phase 1: publish binaries -- ONLY 15 MINUTES BEFORE RELEASE TIME
{% for release in instance.affected_releases %}{% if not release.is_pre_release %}
#### For {{ release.version }}
{% include 'generator/_make_release_public.md' %}{% endif %}{% endfor %}

### Phase 2: final updates
{% include "generator/_stub_release_notes.md" with release=instance.latest_release %}
- [ ]  In the main branch, add security patches entry to archive and backport
  - `git checkout main`
  - Edit `docs/releases/security.txt`
      - Need hashes!
```
{% include 'generator/release_security_archive.rst' %}
```
  - `make html`
  - `git commit -m 'Added {{ cves|enumerate_cves }} to security archive.'`
  - Check links from local docs
      - `firefox _build/html/releases/security.html`
  - Backport security archive update to all branches!
    {% for release in instance.affected_releases %}
    - `git checkout {{ release.stable_branch }} && backport.sh {HASH}`
    {% endfor %}

### Final tasks -- PUSH EVERYTHING TO BRANCHES

- [ ] Push changes to `main` and any stable branch, including pre-releases:
  - `git checkout main && git log && git push -v`
{% for release in instance.affected_releases %}
  - `git checkout {{ release.stable_branch }} && git log`
  - `git push -v`
{% endfor %}
- [ ] Push all the new tags at once
  - `git push --tags`
- [ ] Publish blogpost draft
  - Include hashes!
- [ ] Email to `django-announce@googlegroups.com`
  - Title: `Django security releases issued: {{ versions|enumerate_items }}`
  - Body with short notice and link to blogpost for more details:
```
Details are available on the Django project weblog:
{{ instance.blogpost_link }}
```

- [ ] Post in forum https://forum.djangoproject.com/t/django-release-announcements/655/
  - e.g. https://forum.djangoproject.com/t/django-release-announcements/655/71
```
## Django security releases issued: {{ versions|enumerate_items }}

:mega: Announcement:
{{ instance.blogpost_link }}

:tada: Release notes:{% for version in versions %}
 * https://docs.djangoproject.com/en/dev/releases/{{ version }}{% endfor %}
```
- [ ] Send email to the OSS Security mailing list notifying about the release
  - To: `oss-security@lists.openwall.com`
  - Cc: `security@djangoproject.com`
  - Subject: `Django {{ cves|enumerate_cves }}`
  - Body with blogpost link and content, and CVE data (PASTE blogpost content!!!):
```
* Announce link: {{ instance.blogpost_link }}

* Announce content: <blogpost content>
{% for cve in cves %}
* Machine-readable CVE data for {{ cve }}:
{{ cve.cve_json|safe }}
{% endfor %}
```
- [ ] Notify `mitre.org` about the CVE publication
  {% for cve in cves %}{% include "generator/_cve_publication.md" %}{% endfor %}
- [ ] Close PRs in security repo linking hashes
  {% regroup instance.hashes_by_versions|dictsortreversed:"branch" by branch as items %}
  {% for item in items %}
#### For {{ item.grouper }}
```{% for i in item.list %}
* Fix for {{ i.cve }} merged in https://github.com/django/django/commit/{{ i.hash }}.{% endfor %}
```
  {% endfor %}
- [ ] Close issues in security repo linking hashes
  - e.g. https://github.com/django/django-security/issues/376
  {% regroup instance.hashes_by_versions|dictsort:"cve" by cve as items %}
  {% for item in items %}
#### For {{ item.grouper }}
```
Fixed:{% for i in item.list|dictsortreversed:'branch' %}
* On the [{{ i.branch }} branch](https://github.com/django/django/commit/{{ i.hash }}){% endfor %}
```
  {% endfor %}
- [ ] Remove branches{% endwith %}
