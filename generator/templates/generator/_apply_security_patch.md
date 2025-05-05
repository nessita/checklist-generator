- [ ] Switch to the branch and update it:
  - `git checkout {% if release != "main" %}{{ release.stable_branch }}{% else %}main{% endif %} && git pull -v`
- [ ] Apply patch
  - `git am path/to/patch/for/{{ release }}`
  - `git am --abort` to the rescue if there are issues
{% if release != "main" %}- [ ] Add `{{ release.commit_prefix }}` **prefix** to commit msgs
  - `git commit --amend`{% endif %}
- **SAVE** resulting hash for later.
  - `git show`
