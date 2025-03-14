{% load generator_extras %}
- [ ] Switch to the stable branch:
  - `git checkout {{ release.stable_branch }} && git pull -v`
- [ ] Apply patch
  - `git am path/to/patch/for/{{ release.version }}`
  - `git am --abort` to the rescue if there are issues
- [ ] Add `{{ release.commit_prefix }}` **prefix** to commit msgs
  - `git commit --amend`
  - **SAVE** resulting hash for later, add it to blogpost draft and security PR
- [ ] Change version in `django/__init__.py`
  - `alpha` -> `final`
  - `git commit -m '{{ release.commit_prefix }} Bumped version for {{ release.version }} release.'`
- [ ] RUN script to do the release:
  - `do_django_release.py`
  - Record commands shown at the end. Execute all but leave `git push --tags`,
    both `scp` of binaries, and `twine upload` for later because it's a security
    release.
- [ ] BUMP **MINOR VERSION** in `django/__init__.py`
  - `{{ release.version }}` -> `{{ release|next_version }}`
  - `final` -> `alpha`
  - `git commit -m '{{ release.commit_prefix }} Post-release version bump.'`
