{% load generator_extras %}
{% load partials %}
In accordance with `our security release policy
<https://docs.djangoproject.com/en/dev/internals/security/>`_, the Django team
is issuing releases for
{{ versions|format_versions_for_blogpost|safe|wordwrap:79 }}.
These releases address the security issues detailed below. We encourage all
users of Django to upgrade as soon as possible.
{% for cve in cves %}
{{ cve.headline_for_blogpost|rst_underline_for_headline:'=' }}

{{ cve.blogdescription|default:cve.description|wordwrap:80 }}
{% if cve.reporter %}
Thanks to {{ cve.reporter }} for the report.
{% endif %}
This issue has severity "{{ cve.severity }}" according to the Django security policy.
{% endfor %}

Affected supported versions
===========================
{% for branch in affected_branches %}
* Django {{ branch }}{% endfor %}

Resolution
==========

Patches to resolve the issue have been applied to Django's
{{ affected_branches|enumerate_items }} branches.
The patches may be obtained from the following changesets.
{% for cve in cves %}
{{ cve.headline_for_blogpost|rst_underline_for_headline:'-' }}
{% for branch, hash in cve.hashes_by_branch %}
* On the `{{ branch }} branch <https://github.com/django/django/commit/{{ hash }}>`__{% endfor %}
{% endfor %}

The following releases have been issued
=======================================
{% for version in versions %}
* Django {{ version }} (`download Django {{ version }}
  <https://www.djangoproject.com/m/releases/{{ version|major_minor_version }}/Django-{{ version }}.tar.gz>`_ |
  `{{ version }} checksums
  <https://www.djangoproject.com/m/pgp/Django-{{ version }}.checksum.txt>`_){% endfor %}
{% partialdef releaser-data inline %}
The PGP key ID used for this release is {{ releaser.user.get_full_name }}: `{{ releaser.key_id }} <{{ releaser.key_url }}>`_
{% endpartialdef %}
General notes regarding security reporting
==========================================

As always, we ask that potential security issues be reported via private email
to ``security@djangoproject.com``, and not via Django's Trac instance, nor via
the Django Forum. Please see `our security policies
<https://www.djangoproject.com/security/>`_ for further information.
