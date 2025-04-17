{% load generator_extras %}
Please allocate CVE IDs for the following issues:{% for cve in cves %}{% with releases=cve.releases.all %}

- For issue "{{ cve.summary }}":
    - Affected Django versions:
      {% for release in releases %}{% if not release.is_pre_release %}
      {{ release|format_release_for_cve }}
      {% endfor %}
    - Impact info: {{ cve.impact }}
    - Description of the vulnerability:

      An issue was discovered in {{ releases|format_releases_for_cves }}.
      {{ cve.description }}

    - Discoverer(s)/Credits info: `{{ cve.reporter }}`
{% endwith %}{% endfor %}
