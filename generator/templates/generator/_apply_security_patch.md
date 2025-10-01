- [ ] Switch to the branch and update it:
  - `git checkout {% if release != "main" %}{{ release.stable_branch }}{% else %}main{% endif %} && git pull -v`
- [ ] Apply patch
  - `git am path/to/patch/for/{{ release }}`
  - `git am --abort` to the rescue if there are issues
{% if release != "main" %}- [ ] **Amend** the commit message and record resulting hash:
  - `git commit --amend && git show`
  - Add `{{ release.commit_prefix }}` **prefix** to first line of commit msg
  - Append `Backport of {HASH-FROM-MAIN} from main.` at the end
{% else %}- [ ] **SAVE** resulting hash for later.
  - `git show`{% endif %}
