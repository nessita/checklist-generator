{% load generator_extras %}
- [ ] Switch to the stable branch:
  - `git checkout {{ version|stable_branch }} && git pull -v`
- [ ] Apply patch
  - `git am path/to/patch/for/{{ version }}`
  - `git am --abort` to the rescue if there are issues
- [ ] Add `[{{ version|series }}]` **prefix** to commit msgs
  - `git commit --amend`
  - **SAVE** resulting hash for later, add it to blogpost draft and security PR
- [ ] Change version in `django/__init__.py`
  - `alpha` -> `final`
  - Commit message: `[{{ version|series }}] Bumped version for {{ version }} release.`
- [ ] RUN script to do the release:
  - `do_django_release.py`
  - Record commands shown at the end. Execute all but leave both `scp` of
    binaries and `twine upload` for later because it's a security release.
- [ ] BUMP **MINOR VERSION** in `django/__init__.py`
  - `{{ version }}` -> `{{ version|next_version }}`
  - `final` -> `alpha`
  - Commit message: `[{{ version|series }}] Post-release version bump.`
