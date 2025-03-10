{% load generator_extras %}
{% for cve in cves %}
{{ cve.headline_for_archive|rst_underline_for_headline:"-" }}

{{ cve.summary }}.
`Full description
<{{ instance.blogpost_link }}>`__
{% for branch, hash in cve.hashes_by_branch %}
{% if branch != 'main' %}* Django {{ branch }} :commit:`(patch) <{{ hash }}>`{% endif %}{% endfor %}
{% endfor %}
