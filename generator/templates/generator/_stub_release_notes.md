{% load generator_extras %}
- [ ] In the `main` branch, start release notes for the next version only for the latest stable branch:

    - `git checkout main`{% with next_version=release|next_version %}
    - Edit `docs/releases/index.txt` and add an entry for `{{ next_version }}`
    - Create empty file for release at `docs/releases/{{ next_version }}.txt`:
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
        - `make html check`
    - Add the new file and commit
        - `git add docs/releases/{{ next_version }}.txt`
        - `git commit -a -m 'Added stub release notes for {{ next_version }}.'`
    - Backport new release notes to latest stable branch!
        - `backport.sh {HASH}`{% endwith %}
