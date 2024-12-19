{% load generator_extras %}
- [ ] Ensure separated folder in origin.djangoproject.com for the release (this should be the case already)
  - `ssh www@origin.djangoproject.com 'ls -l /home/www/www/media/releases/{{ version|major_minor_version }}'`
- [ ] **ONLY SCP** each binary set (tar.gz and wheel) to the corresponding folder (use commands from before)
- [ ] CONFIRM RELEASE via jenkins job
  - https://djangoci.com/job/confirm-release/ "Build with parameters" passing `{{ version }}` as version
- [ ] Run test new version script
- [ ] Add a new Release entry in djangoproject.com/admin for {{ version }}
- [ ] Twine upload (use commands printed by release script)
