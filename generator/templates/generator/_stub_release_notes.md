{% load generator_extras %}
- [ ] In the `main` branch, start release notes for the next version only for the latest stable branch:
  - `git checkout main`{% with next_version=release|next_version %}
  - Edit `docs/releases/index.txt` and add an entry for `{{ next_version }}`
  - Create empty file for release at `docs/releases/{{ next_version }}.txt`
      - Add basic content:

        ```
        ==========================
        Django {{ next_version }} release notes
        ==========================

        *Expected {{ release.date|next_release_date|date:"F j, Y" }}*

        Django {{ next_version }} fixes several bugs in {{ release.version }}.

        Bugfixes
        ========

        * ...

        ```
  - Confirm docs works
      - `make html`
  - Commit
      - `git commit -m 'Added stub release notes for {{ next_version }}.'`
  - Backport new release notes to latest stable branch!
      -  `backport.sh {HASH}`{% endwith %}
