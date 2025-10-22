- [ ] Edit the the [release entry in the admin](https://www.djangoproject.com/admin/releases/release/{{ release }}/):
    - Is active: False
    - LTS: {{ release.is_lts }}
    - Release date: {{ release.date.isoformat }}
    - End of life date: _blank_
    - Upload artifacts (tarball, wheel, .asc signed checksum)
    - Save
    - Check at: https://www.djangoproject.com/admin/releases/release/{{ release }}/change/

- [ ] Test the release locally with https://code.djangoproject.com/wiki/ReleaseTestNewVersion
    - `RELEASE_VERSION={{ release }} test_new_version.sh`

- [ ] CONFIRM RELEASE via jenkins job
    - https://djangoci.com/job/confirm-release/ "Build with parameters" passing
    version: `{{ release.version }}`

- [ ] Upload to PyPI with Twine (use commands printed by release script)
    - `twine upload --repository django dist/*`
    - https://pypi.org/project/Django/{{ release }}/

- [ ] Mark the release as "active" in
  https://www.djangoproject.com/admin/releases/release/{{ release }}/change/
