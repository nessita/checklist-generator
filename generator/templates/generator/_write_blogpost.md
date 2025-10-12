- [ ] Create blog post:
    - Headline: `{{ instance.blogpost_title }}`
    - Slug: `{{ slug }}`
    - Format: reStructuredText
    - Summary: `{{ instance.blogpost_summary }}`
    - Body:
```
{% include instance.blogpost_template %}
```
