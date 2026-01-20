import datetime

from django.test import SimpleTestCase, TestCase

from generator.models import Release, upload_to_artifact, upload_to_checksum


class TestReleaseManager(TestCase):
    @classmethod
    def setUpTestData(cls):
        today = datetime.date.today()
        day = datetime.timedelta(1)
        Release.objects.create(
            version="1.4",
            is_active=True,
            is_lts=True,
            date=today - 450 * day,
            eol_date=today + 50 * day,
        )
        Release.objects.create(
            version="1.5",
            is_active=True,
            date=today - 350 * day,
            eol_date=today - 150 * day,
        )
        Release.objects.create(
            version="1.6",
            is_active=True,
            date=today - 250 * day,
            eol_date=today - 50 * day,
        )
        Release.objects.create(
            version="1.7",
            is_active=True,
            date=today - 150 * day,
            eol_date=today + 50 * day,
        )
        Release.objects.create(
            version="1.8a1",
            is_active=True,
            date=today - 80 * day,
            eol_date=today - 65 * day,
        )
        Release.objects.create(
            version="1.8b1",
            is_lts=True,
            is_active=True,
            date=today - 65 * day,
            eol_date=today - 50 * day,
        )
        Release.objects.create(
            version="1.8",
            is_lts=True,
            is_active=True,
            date=today - 50 * day,
            eol_date=today,
        )
        Release.objects.create(
            version="1.8.1", is_active=True, is_lts=True, date=today, eol_date=None
        )
        Release.objects.create(version="1.9", is_active=True, date=None, eol_date=None)
        Release.objects.create(
            version="1.10", is_active=False, date=today, eol_date=None
        )

    def test_published(self):
        active_versions = Release.objects.published().values_list("version", flat=True)
        self.assertEqual(list(active_versions), ["1.8.1", "1.7", "1.4"])

    def test_supported(self):
        supported_versions = Release.objects.supported().values_list(
            "version", flat=True
        )
        self.assertEqual(list(supported_versions), ["1.8.1", "1.7", "1.4"])

    def test_unsupported(self):
        unsupported_versions = [r.version for r in Release.objects.unsupported()]
        self.assertEqual(unsupported_versions, ["1.6", "1.5"])

    def test_current(self):
        self.assertEqual(Release.objects.current().version, "1.8.1")
        Release.objects.filter(version="1.8.1").delete()
        self.assertEqual(Release.objects.current().version, "1.7")

    def test_previous(self):
        self.assertEqual(Release.objects.previous().version, "1.7")

    def test_lts(self):
        lts_versions = Release.objects.lts().values_list("version", flat=True)
        self.assertEqual(list(lts_versions), ["1.8.1", "1.4"])

    def test_current_lts(self):
        self.assertEqual(Release.objects.current_lts().version, "1.8.1")
        Release.objects.filter(version="1.8.1").delete()
        self.assertEqual(Release.objects.current_lts().version, "1.4")

    def test_previous_lts(self):
        self.assertEqual(Release.objects.previous_lts().version, "1.4")
        Release.objects.filter(version="1.8.1").delete()
        self.assertEqual(Release.objects.previous_lts(), None)

    def test_preview(self):
        self.assertEqual(Release.objects.preview(), None)
        Release.objects.create(
            version="1.9b2", is_active=True, date=datetime.date.today(), eol_date=None
        )
        self.assertEqual(Release.objects.preview().version, "1.9b2")


class ReleaseTestCase(TestCase):
    def test_is_published(self):
        today = datetime.date.today()
        future = today + datetime.timedelta(days=1)
        past = today - datetime.timedelta(days=1)
        cases = [
            ({"date": None, "is_active": True}, False),
            ({"date": None, "is_active": False}, False),
            ({"date": today, "is_active": True}, True),
            ({"date": today, "is_active": False}, False),
            ({"date": past, "is_active": True}, True),
            ({"date": past, "is_active": False}, False),
            ({"date": future, "is_active": True}, False),
            ({"date": future, "is_active": False}, False),
        ]
        for i, (params, expected) in enumerate(cases):
            with self.subTest(**params, saved=False):
                release = Release(version="1.0", **params)
                self.assertIs(release.is_published, expected)
            with self.subTest(**params, saved=True):
                release = Release.objects.create(version=f"{i}.0", **params)
                self.assertIs(release.is_published, expected)

    def test_save_sets_eol_date(self):
        today = datetime.date.today()
        future = today + datetime.timedelta(days=1)
        past = today - datetime.timedelta(days=1)
        cases = [
            ({"date": None, "is_active": True}, None),
            ({"date": None, "is_active": False}, None),
            ({"date": today, "is_active": True}, today),
            ({"date": today, "is_active": False}, None),
            ({"date": past, "is_active": True}, past),
            ({"date": past, "is_active": False}, None),
            ({"date": future, "is_active": True}, future),
            ({"date": future, "is_active": False}, None),
        ]
        for i, (params, expected_eol_date) in enumerate(cases):
            previous = Release.objects.create(version=f"{i}.1.1")
            release = Release(version=f"{i}.1.2")
            for k, v in params.items():
                setattr(release, k, v)
            release.save()
            previous.refresh_from_db()
            with self.subTest(**params):
                self.assertEqual(previous.eol_date, expected_eol_date)

    def test_save_eol_date_pre_releases(self):
        other_release = Release.objects.create(version="5.1.7", is_active=True)
        today = datetime.date.today()
        cases = [
            ("5.1.1", "5.2a1"),
            ("5.2a1", "5.2a2"),
            ("5.2a2", "5.2b1"),
            ("5.2b1", "5.2rc1"),
            ("5.2rc1", "5.2"),
            ("5.2", "5.2.1"),
        ]
        for previous_version, next_version in cases:
            with self.subTest(msg=f"{previous_version} -> {next_version}"):
                previous_release, _ = Release.objects.get_or_create(
                    version=previous_version,
                    is_active=True,
                )
                self.assertIsNone(previous_release.eol_date)
                next_release = Release.objects.create(
                    version=next_version, is_active=True
                )
                previous_release.refresh_from_db()
                other_release.refresh_from_db()
                if next_release.version_tuple[-2:] != ("alpha", 1):
                    self.assertEqual(previous_release.eol_date, today)
                self.assertIsNone(next_release.eol_date)
                self.assertIsNone(other_release.eol_date)

    def test_version_tuple(self):
        cases = [
            ("1.0", (1, 0, 0, "final", 0)),
            ("1.8", (1, 8, 0, "final", 0)),
            ("1.8.1", (1, 8, 1, "final", 0)),
            ("1.8a1", (1, 8, 0, "alpha", 1)),
            ("1.8b1", (1, 8, 0, "beta", 1)),
            ("1.8rc1", (1, 8, 0, "rc", 1)),
            ("5.2", (5, 2, 0, "final", 0)),
            ("5.2a1", (5, 2, 0, "alpha", 1)),
        ]
        for version, expected in cases:
            with self.subTest(version=version):
                release = Release.objects.create(version=version)
                self.assertEqual(release.version_tuple, expected)

    def test_version_verbose(self):
        cases = [
            ("5.2a1", "5.2 alpha 1"),
            ("5.2a2", "5.2 alpha 2"),
            ("5.2b1", "5.2 beta 1"),
            ("5.2rc1", "5.2 release candidate 1"),
            ("5.2", "5.2"),
            ("5.2.1", "5.2.1"),
        ]
        for version, expected in cases:
            with self.subTest(version=version):
                release = Release.objects.create(version=version)
                self.assertEqual(release.version_verbose, expected)

    def test_feature_version(self):
        cases = [
            ("5.2", "5.2"),
            ("5.2a1", "5.2"),
            ("5.2.1", "5.2"),
            ("5.2.15", "5.2"),
            ("4.1rc1", "4.1"),
        ]
        for version, expected in cases:
            with self.subTest(version=version):
                release = Release.objects.create(version=version)
                self.assertEqual(release.feature_version, expected)

    def test_feature_release(self):
        feature = Release.objects.create(version="5.2")

        # Feature release itself should return itself.
        self.assertEqual(feature.feature_release, feature)
        self.assertEqual(feature.feature_release.version, "5.2")

        # All other versions in the series should return the feature release
        cases = ["5.2a1", "5.2b1", "5.2rc1", "5.2.1", "5.2.2"]
        for version in cases:
            with self.subTest(version=version):
                release = Release.objects.create(version=version)
                self.assertEqual(release.feature_release, feature)
                self.assertEqual(release.feature_release.version, "5.2")

    def test_series(self):
        cases = [
            ("5.2", "5.x"),
            ("5.2.1", "5.x"),
            ("4.1", "4.x"),
            ("3.2rc1", "3.x"),
        ]
        for version, expected in cases:
            with self.subTest(version=version):
                release = Release.objects.create(version=version)
                self.assertEqual(release.series, expected)

    def test_stable_branch(self):
        cases = [
            ("5.2", "stable/5.2.x"),
            ("5.2.1", "stable/5.2.x"),
            ("4.1rc1", "stable/4.1.x"),
        ]
        for version, expected in cases:
            with self.subTest(version=version):
                release = Release.objects.create(version=version)
                self.assertEqual(release.stable_branch, expected)

    def test_commit_prefix(self):
        cases = [
            ("5.2", "[5.2.x]"),
            ("5.2.1", "[5.2.x]"),
            ("4.1rc1", "[4.1.x]"),
        ]
        for version, expected in cases:
            with self.subTest(version=version):
                release = Release.objects.create(version=version)
                self.assertEqual(release.commit_prefix, expected)

    def test_is_pre_release(self):
        cases = [
            ("5.2a1", True),
            ("5.2b1", True),
            ("5.2rc1", True),
            ("5.2", False),
            ("5.2.1", False),
        ]
        for version, expected in cases:
            with self.subTest(version=version):
                release = Release.objects.create(version=version)
                self.assertIs(release.is_pre_release, expected)

    def test_is_dot_zero(self):
        cases = [
            ("5.2", True),
            ("4.1", True),
            ("5.2.1", False),
            ("5.2.15", False),
            ("5.2a1", False),
            ("5.2rc1", False),
        ]
        for version, expected in cases:
            with self.subTest(version=version):
                release = Release.objects.create(version=version)
                self.assertIs(release.is_dot_zero, expected)

    def test_ordering(self):
        r1 = Release.objects.create(version="5.2")
        r2 = Release.objects.create(version="5.2.1")
        r3 = Release.objects.create(version="6.0a1")
        r4 = Release.objects.create(version="6.0")

        # Comparison.
        self.assertLessEqual(r1, r1)
        self.assertLess(r1, r2)
        self.assertLess(r2, r3)
        self.assertLess(r1, r3)
        self.assertLess(r3, r4)
        self.assertGreater(r2, r1)
        self.assertGreaterEqual(r1, r1)

        # Sorting.
        releases = [r3, r1, r2, r4]
        self.assertEqual(sorted(releases), [r1, r2, r3, r4])

    def test_release_hash(self):
        r1 = Release.objects.create(version="5.2")
        r2 = Release.objects.create(version="5.2.1")

        self.assertEqual({r1, r2, r1}, {r1, r2})
        self.assertNotEqual(hash(r1), hash(r2))
        self.assertEqual(hash(r1), hash(r1))


class ReleaseUploadToTestCase(SimpleTestCase):
    def test_upload_to_artifact(self):
        for version, filename, expected in [
            ("5.2", "django-5.2.tar.gz", "releases/5.2/django-5.2.tar.gz"),
            ("5.2", "django-5.2.tar.xz", "releases/5.2/django-5.2.tar.xz"),
            ("5.2", "Django-5.2.tar.gz", "releases/5.2/Django-5.2.tar.gz"),
            ("5.2", "DJANGO-5.2.tar.gz", "releases/5.2/DJANGO-5.2.tar.gz"),
            ("5.2.1", "django-5.2.1.tar.gz", "releases/5.2/django-5.2.1.tar.gz"),
            ("5.2a1", "django-5.2a1.tar.gz", "releases/5.2/django-5.2a1.tar.gz"),
            ("5.2b2", "django-5.2b2.tar.gz", "releases/5.2/django-5.2b2.tar.gz"),
            ("5.2rc3", "django-5.2rc3.tar.gz", "releases/5.2/django-5.2rc3.tar.gz"),
            ("5.2", "django-5.2-py3-none.whl", "releases/5.2/django-5.2-py3-none.whl"),
            ("5.2", "Django-5.2-py3-none.whl", "releases/5.2/Django-5.2-py3-none.whl"),
            ("5.2", "DJANGO-5.2-py3-none.whl", "releases/5.2/DJANGO-5.2-py3-none.whl"),
            (
                "5.2.1",
                "django-5.2.1-py3-none.whl",
                "releases/5.2/django-5.2.1-py3-none.whl",
            ),
            (
                "5.2a1",
                "django-5.2a1-py3-none.whl",
                "releases/5.2/django-5.2a1-py3-none.whl",
            ),
            (
                "5.2b2",
                "django-5.2b2-py3-none.whl",
                "releases/5.2/django-5.2b2-py3-none.whl",
            ),
        ]:
            with self.subTest(version=version, filename=filename):
                self.assertEqual(
                    upload_to_artifact(Release(version=version), filename=filename),
                    expected,
                )

    def test_upload_to_checksum(self):
        for version, expected in [
            ("5.2", "pgp/Django-5.2.checksum.txt"),
            ("5.2.1", "pgp/Django-5.2.1.checksum.txt"),
            ("5.2a1", "pgp/Django-5.2a1.checksum.txt"),
            ("5.2b2", "pgp/Django-5.2b2.checksum.txt"),
        ]:
            with self.subTest(version=version):
                self.assertEqual(
                    # filename should not matter
                    upload_to_checksum(Release(version=version), filename=None),
                    expected,
                )
