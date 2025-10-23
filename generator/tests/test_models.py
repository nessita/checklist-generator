import json
import re
from datetime import UTC, date, datetime

from django.template.loader import render_to_string
from django.test import RequestFactory, TestCase, override_settings
from django.utils.timezone import make_aware

from generator.models import (
    SEVERITY_LEVELS_DOCS,
    BugFixRelease,
    FeatureRelease,
    PreRelease,
    SecurityRelease,
)
from generator.tests.factory import Factory


class BaseChecklistTestCaseMixin:
    checklist_class = None
    factory = Factory()
    request_factory = RequestFactory()

    def debug_checklist(self, content):
        fname = f"{self.id()}-checklist.md"
        with open(fname, "w") as f:
            f.write(content)
        return fname

    def make_checklist(self, releaser=None, when=None, **kwargs):
        return self.factory.make_checklist(
            self.checklist_class, releaser=releaser, when=when, **kwargs
        )

    def assertInChecklistContent(self, text, content, flat=False):
        """Like assertIn, but without worrying about whitespaces."""
        if flat:
            # Collapse all whitespace to single spaces.
            content = re.sub(r"\s+", " ", content)
        if text not in content:
            fname = self.debug_checklist(content)
            self.fail(
                f"The given:\n{text}\nis not in the checklist content, which was "
                f"stored in {fname} for further debugging."
            )

    def assertNotInChecklistContent(self, text, content):
        """Show more readable error message on `assertNotIn` failures."""
        idx = content.find(text)
        if idx != -1:
            start = max(idx - 10, 0)
            end = min(start + 100, len(content))
            fragment = content[start:end]
            self.fail(f"{text!r} unexpectedly found in:\n{fragment}")

    def assertStubReleaseNotesAdded(self, release, content):
        expected = render_to_string(
            "generator/_stub_release_notes.md", {"release": release}
        )
        self.assertIn(expected, content)

    def assertMakeReleasePublicAdded(self, release, content):
        expected = render_to_string(
            "generator/_make_release_public.md", {"release": release}
        )
        self.assertIn(expected, content)
        version = release.version
        data = [
            "- [ ] Edit the the [release entry in the admin]"
            f"(https://www.djangoproject.com/admin/releases/release/{version}/)",
            "- Is active: False",
            f"- LTS: {release.is_lts}",
            f"- Release date: {release.date.isoformat()}",
            f"- `RELEASE_VERSION={version} test_new_version.sh`",
            '- https://djangoci.com/job/confirm-release/ "Build with parameters" '
            f"passing\n    version: `{version}`",
            "- `twine upload --repository django dist/*`",
            '- [ ] Mark the release as "active" in\n  '
            f"https://www.djangoproject.com/admin/releases/release/{version}/change/",
        ]
        for item in data:
            with self.subTest(item=item):
                self.assertIn(item, expected)

    def assertPushAndAnnouncesAdded(self, instance, content):
        expected = render_to_string(
            "generator/_push_changes_and_announce.md",
            context={
                "instance": instance,
                "releaser": instance.releaser,
                "slug": instance.slug,
                "version": instance.version,
                "title": instance.__class__.__name__,
                **instance.__dict__,
            },
        )
        self.assertIn(expected, content)
        data = [
            "- `git push -v`",
            "- `git push --tags`",
        ]
        for item in data:
            with self.subTest(item=item):
                self.assertIn(item, expected)

    @override_settings(
        TEMPLATES=[
            {
                "BACKEND": "django.template.backends.django.DjangoTemplates",
                "DIRS": [],
                "APP_DIRS": True,
                "OPTIONS": {
                    "context_processors": [],
                    "string_if_invalid": "INVALID: %s",
                },
            }
        ]
    )
    def do_render_checklist(self, checklist_instance=None):
        if checklist_instance is None:
            checklist_instance = self.make_checklist()

        request = self.request_factory.get("/")
        content = checklist_instance.render_to_string(request)
        self.assertNotInChecklistContent("INVALID", content)

        return content


class BugFixReleaseChecklistTestCase(BaseChecklistTestCaseMixin, TestCase):
    checklist_class = BugFixRelease

    def test_render_checklist(self):
        release = self.factory.make_release(version="5.2.4")
        checklist_instance = self.make_checklist(release=release)
        checklist_content = self.do_render_checklist(checklist_instance)
        self.assertPushAndAnnouncesAdded(checklist_instance, checklist_content)
        self.assertStubReleaseNotesAdded(release, checklist_content)
        self.assertMakeReleasePublicAdded(release, checklist_content)


class SecurityReleaseChecklistTestCase(BaseChecklistTestCaseMixin, TestCase):
    checklist_class = SecurityRelease

    def make_checklist(self, releaser=None, when=None, **kwargs):
        return self.factory.make_security_checklist(
            releaser=releaser, when=when, **kwargs
        )

    def test_affected_releases(self):
        release51 = self.factory.make_release(version="5.1.8")
        release52 = self.factory.make_release(version="5.2")
        prerelease = self.factory.make_release(version="6.0a1")
        checklist = self.make_checklist(releases=[release51, release52, prerelease])
        self.assertEqual(
            checklist.affected_releases, [prerelease, release52, release51]
        )

    def test_blogpost_info(self):
        release42 = self.factory.make_release(version="4.2.13")
        release51 = self.factory.make_release(version="5.1.7")
        release52 = self.factory.make_release(version="5.2")
        prerelease = self.factory.make_release(version="6.0a1")
        # Test proper use of Oxford comma.
        for releases, expected, verb in [
            ([release52], "5.2", "fixes"),
            ([release52, prerelease], "5.2", "fixes"),
            ([release52, release51, prerelease], "5.2 and 5.1.7", "fix"),
            (
                [release52, release51, release42, prerelease],
                "5.2, 5.1.7, and 4.2.13",
                "fix",
            ),
        ]:
            with self.subTest(releases=releases):
                checklist = self.make_checklist(releases=releases)
                self.assertEqual(
                    checklist.blogpost_title,
                    f"Django security releases issued: {expected}",
                )
                self.assertEqual(
                    checklist.blogpost_summary,
                    f"Django {expected} {verb} one security issue",
                )

    def test_blogpost_info_two_issues(self):
        release51 = self.factory.make_release(version="5.1.9")
        release52 = self.factory.make_release(version="5.2")
        prerelease = self.factory.make_release(version="6.0a1")
        checklist = self.make_checklist(releases=[release51, release52, prerelease])
        self.factory.make_security_issue(checklist, releases=[release52])
        self.assertEqual(
            checklist.blogpost_template, "generator/release_security_blogpost.rst"
        )
        self.assertEqual(
            checklist.blogpost_summary, "Django 5.2 and 5.1.9 fix 2 security issues"
        )

    def test_versions(self):
        release51 = self.factory.make_release(version="5.1.9")
        release52 = self.factory.make_release(version="5.2")
        prerelease = self.factory.make_release(version="6.0a1")
        checklist = self.make_checklist(releases=[release51, release52, prerelease])
        self.assertEqual(checklist.version, "5.2 and 5.1.9")
        self.assertEqual(checklist.versions, ["5.2", "5.1.9"])

    def test_render_checklist_simple(self):
        checklist = self.make_checklist()
        checklist_content = self.do_render_checklist(checklist)
        self.assertIn(
            "- [ ] Submit a CVE Request https://cveform.mitre.org for all issues",
            checklist_content,
        )

        with self.subTest(task="One Week before steps"):
            self.assertIn("## One Week before", checklist_content)
            self.assertIn(
                "- [ ] Land the stub release notes and release date updates in main "
                "and 5.2",
                checklist_content,
            )

        with self.subTest(task="Stub release notes added"):
            self.assertStubReleaseNotesAdded(
                checklist.latest_release, checklist_content
            )

        with self.subTest(task="Make release public steps added"):
            self.assertMakeReleasePublicAdded(
                checklist.latest_release, checklist_content
            )

        with self.subTest(task="Push and announce steps added"):
            self.assertPushAndAnnouncesAdded(checklist, checklist_content)

    def test_render_checklist_affects_prerelease(self):
        releases = [
            self.factory.make_release(version="5.0.14", date=date(2025, 4, 2)),
            self.factory.make_release(version="5.1.8", date=date(2025, 4, 2)),
            self.factory.make_release(version="5.2rc1", date=date(2025, 3, 19)),
        ]
        when = datetime(2025, 5, 7, 11, 18, 23, tzinfo=UTC)
        checklist = self.make_checklist(releases=[], when=when)
        self.factory.make_security_issue(
            checklist, releases, cve_year_number="CVE-2025-11111"
        )
        self.factory.make_security_issue(
            checklist, releases, cve_year_number="CVE-2025-22222"
        )

        checklist_content = self.do_render_checklist(checklist)

        self.assertNotInChecklistContent("5.2 before 5.2rc1", checklist_content)
        self.assertIn(
            "- Affected product(s)/code base (SPLIT in product and version (X before Y)"
            " in rows!):",
            checklist_content,
        )
        for release in ("5.1 before 5.1.8", "5.0 before 5.0.14"):
            with self.subTest(release=release):
                expected = f"[row 1] Django [row 2] {release}"
                self.assertInChecklistContent(expected, checklist_content, flat=True)

        cves = checklist.securityissue_set.all()
        prenotification = [
            "Create a new text file `prenotification-email.txt` with content",
            "a set of security releases will be issued on Wednesday, May 7, 2025 "
            "around 11:18 UTC",
            *(cve.headline_for_blogpost for cve in cves),
            "Affected supported versions =========================== "
            + " ".join(f"* Django {branch}" for branch in checklist.affected_branches),
            "* Django 5.0.14",
            "* Django 5.1.8",
        ]
        for detail in prenotification:
            with self.subTest(detail=detail):
                self.assertInChecklistContent(detail, checklist_content, flat=True)

    def test_render_checklist_blogdescription_display(self):
        checklist = self.make_checklist(releases=[])
        blog = (
            "This is a blog description that would be used in the Django site "
            '"News" section. The full list of news can be found `in this link '
            "<https://www.djangoproject.com/weblog/>`_."
        )
        self.factory.make_security_issue(checklist, blogdescription=blog)

        checklist_content = self.do_render_checklist(checklist)

        self.assertIn(
            "- [ ] Submit a CVE Request https://cveform.mitre.org for all issues",
            checklist_content,
        )
        self.assertIn(blog, checklist_content)

    def test_render_checklist_download_links(self):
        releases = [
            self.factory.make_release(version="4.2.21"),
            self.factory.make_release(version="5.1.9"),
            self.factory.make_release(version="5.2rc1"),
        ]
        checklist = self.make_checklist(releases=releases)
        checklist_content = self.do_render_checklist(checklist)

        expected = (
            "The following releases have been issued\n"
            "=======================================\n"
            "\n"
            "* Django 5.1.9 (`download Django 5.1.9\n"
            "  <https://www.djangoproject.com/download/5.1.9/tarball/>`_ |\n"
            "  `5.1.9 checksums\n"
            "  <https://www.djangoproject.com/download/5.1.9/checksum/>`_)\n"
            "* Django 4.2.21 (`download Django 4.2.21\n"
            "  <https://www.djangoproject.com/download/4.2.21/tarball/>`_ |\n"
            "  `4.2.21 checksums\n"
            "  <https://www.djangoproject.com/download/4.2.21/checksum/>`_)\n"
            "\n"
            "The PGP key ID used for this release is Merry Pippin: "
            "`1234567890ABCDEF <https://github.com/releaser.gpg>`_\n"
        )
        # Proper download links are shown.
        self.assertIn(expected, checklist_content)

    def test_render_checklist_rst_backticks(self):
        releases = [
            self.factory.make_release(version="5.1.9"),
            self.factory.make_release(version="5.2.1"),
        ]
        checklist = self.make_checklist(
            releases=[], when=datetime(2025, 5, 7, tzinfo=UTC)
        )
        self.factory.make_security_issue(
            checklist,
            releases,
            cve_year_number="CVE-2025-11111",
            summary="Denial-of-service possibility in `strip_tags()`",
        )
        self.factory.make_security_issue(
            checklist,
            releases,
            cve_year_number="CVE-2025-22222",
            summary="Denial-of-service in `LoginView` and `LogoutView`",
        )
        checklist_content = self.do_render_checklist(checklist)

        expected = [
            "CVE-2025-11111: Denial-of-service possibility in ``strip_tags()``\n"
            "=================================================================\n",
            "CVE-2025-11111: Denial-of-service possibility in ``strip_tags()``\n"
            "-----------------------------------------------------------------\n",
            "CVE-2025-22222: Denial-of-service in ``LoginView`` and ``LogoutView``\n"
            "=====================================================================\n",
            "CVE-2025-22222: Denial-of-service in ``LoginView`` and ``LogoutView``\n"
            "---------------------------------------------------------------------\n",
            "May 7, 2025 - :cve:`2025-11111`\n"
            "-------------------------------\n\n"
            "Denial-of-service possibility in ``strip_tags()``.\n"
            f"`Full description\n<{checklist.blogpost_link}>`__",
            "May 7, 2025 - :cve:`2025-22222`\n"
            "-------------------------------\n\n"
            "Denial-of-service in ``LoginView`` and ``LogoutView``.\n"
            f"`Full description\n<{checklist.blogpost_link}>`__",
        ]
        for headline in expected:
            with self.subTest(headline=headline):
                self.assertIn(headline, checklist_content)

    def test_render_cve_json(self):
        releases = [
            self.factory.make_release(version="5.0.14", date=date(2025, 4, 2)),
            self.factory.make_release(version="5.1.8", date=date(2025, 4, 2)),
            self.factory.make_release(version="5.2rc1", date=date(2025, 3, 19)),
        ]
        when = datetime(2024, 12, 4, 10)
        checklist = self.make_checklist(
            releases=[],
            when=make_aware(when),
        )
        cve_number = "CVE-2024-53907"
        cve_summary = "Potential denial-of-service in django.utils.html.strip_tags()"
        cve_description = (
            "The strip_tags() method and striptags template filter are subject to a "
            "potential denial-of-service attack via certain inputs containing large "
            "sequences of nested incomplete HTML entities."
        )
        reporter = "jiangniao"
        issue = self.factory.make_security_issue(
            checklist,
            releases,
            cve_year_number=cve_number,
            summary=cve_summary,
            description=cve_description,
            reporter=reporter,
        )
        checklist_content = self.do_render_checklist(checklist)

        affected_versions = [
            {
                "collectionURL": "https://github.com/django/django/",
                "defaultStatus": "affected",
                "packageName": "django",
                "versions": [
                    {
                        "lessThan": "5.1.8",
                        "status": "affected",
                        "version": "5.1.0",
                        "versionType": "semver",
                    },
                    {
                        "lessThan": "5.1.*",
                        "status": "unaffected",
                        "version": "5.1.8",
                        "versionType": "semver",
                    },
                    {
                        "lessThan": "5.0.14",
                        "status": "affected",
                        "version": "5.0.0",
                        "versionType": "semver",
                    },
                    {
                        "lessThan": "5.0.*",
                        "status": "unaffected",
                        "version": "5.0.14",
                        "versionType": "semver",
                    },
                ],
            }
        ]
        credits = [
            {
                "lang": "en",
                "type": "reporter",
                "value": (
                    f"Django would like to thank {reporter} for reporting this issue."
                ),
            }
        ]
        expected = [
            ("affected", affected_versions),
            ("credits", credits),
            ("datePublic", "12/04/2024"),
            ("descriptions", [{"lang": "en", "value": cve_description}]),
            (
                "metrics",
                [
                    {
                        "other": {
                            "content": {
                                "namespace": SEVERITY_LEVELS_DOCS,
                                "value": "moderate",
                            },
                            "type": "Django severity rating",
                        }
                    }
                ],
            ),
            (
                "references",
                [
                    {
                        "name": "Django security releases issued: 5.1.8 and 5.0.14",
                        "tags": ["vendor-advisory"],
                        "url": checklist.blogpost_link,
                    }
                ],
            ),
            (
                "timeline",
                [
                    {
                        "lang": "en",
                        "time": checklist.when.isoformat(),
                        "value": "Made public.",
                    }
                ],
            ),
            ("title", cve_summary),
        ]
        cve_data = issue.cve_data
        for key, value in expected:
            with self.subTest(key=key):
                self.assertEqual(cve_data.get(key), value)

        cve_json = json.dumps(cve_data, sort_keys=True, indent=2)
        with self.subTest(key="json"):
            self.assertIn(cve_json, checklist_content)


class PreReleaseChecklistTestCase(BaseChecklistTestCaseMixin, TestCase):
    checklist_class = PreRelease
    status_to_version = {
        "a": "alpha",
        "b": "beta",
        "rc": "release candidate",
    }

    def test_affected_releases(self):
        feature_release = self.factory.make_feature_release_checklist("6.0")
        for status, verbose in self.status_to_version.items():
            release = self.factory.make_release(version=f"6.0{status}1")
            with self.subTest(release=release):
                checklist = self.make_checklist(
                    feature_release=feature_release, release=release
                )
                self.assertEqual(checklist.affected_releases, [release])

    def test_blogpost_info(self):
        feature_release = self.factory.make_feature_release_checklist("6.0")
        for status, verbose in self.status_to_version.items():
            release = self.factory.make_release(version=f"6.0{status}1")
            with self.subTest(release=release):
                checklist = self.make_checklist(
                    feature_release=feature_release, release=release
                )
                self.assertEqual(
                    checklist.blogpost_title, f"Django 6.0 {verbose} 1 released"
                )
                self.assertEqual(
                    checklist.blogpost_template,
                    f"generator/release_{checklist.status_reversed}_blogpost.rst",
                )
                expected = (
                    f"Today Django 6.0 {verbose} 1, a preview/testing package for the "
                    f"upcoming Django 6.0 release, is available."
                )
                self.assertEqual(checklist.blogpost_summary, expected)

    def test_versions(self):
        feature_release = self.factory.make_feature_release_checklist("6.0")
        for status, verbose in self.status_to_version.items():
            version = f"6.0{status}1"
            release = self.factory.make_release(version=version)
            with self.subTest(release=release):
                checklist = self.make_checklist(
                    feature_release=feature_release, release=release
                )
                self.assertEqual(checklist.version, version)
                self.assertEqual(checklist.versions, [version])

    def test_render_checklist(self):
        feature_release = self.factory.make_feature_release_checklist("5.2")
        for status, version in self.status_to_version.items():
            release = self.factory.make_release(
                version=f"5.2{status}1", date=date(2025, 4, 2), is_lts=True
            )
            with self.subTest(version=version):
                instance = self.make_checklist(
                    feature_release=feature_release, release=release
                )
                assert instance.release is release
                checklist_content = self.do_render_checklist(instance)
                self.assertIn(
                    "- [ ] Update the translation catalogs:", checklist_content
                )
                if status == "rc":
                    self.assertIn(
                        "- [ ] Post on Forum calling for translations!",
                        checklist_content,
                    )
                else:
                    self.assertNotInChecklistContent(
                        "- [ ] Post on Forum calling for translations!",
                        checklist_content,
                    )

                final_version_correct = f"Django 5.2 {version} 1 is now available."
                self.assertIn(final_version_correct, checklist_content)


class FeatureReleaseChecklistTestCase(BaseChecklistTestCaseMixin, TestCase):
    checklist_class = FeatureRelease

    def test_affected_releases(self):
        release = self.factory.make_release(version="6.0")
        checklist = self.make_checklist(release=release)
        self.assertEqual(checklist.affected_releases, [release])

    def test_blogpost_info(self):
        release = self.factory.make_release(version="6.0")
        checklist = self.make_checklist(release=release)
        self.assertEqual(checklist.blogpost_title, "Django 6.0 released")
        self.assertEqual(
            checklist.blogpost_template, "generator/release_final_blogpost.rst"
        )
        self.assertEqual(checklist.blogpost_summary, "Django 6.0 has been released!")

    def test_versions(self):
        release = self.factory.make_release(version="6.0")
        checklist = self.make_checklist(release=release)
        self.assertEqual(checklist.version, "6.0")
        self.assertEqual(checklist.versions, ["6.0"])

    def test_render_checklist(self):
        eol_release = self.factory.make_release(version="5.0", date=date(2023, 12, 4))
        eom_release = self.factory.make_release(version="5.1", date=date(2024, 9, 2))
        release = self.factory.make_release(version="5.2", date=date(2025, 4, 2))
        checklist = self.make_checklist(
            release=release, eom_release=eom_release, eol_release=eol_release
        )
        checklist_content = self.do_render_checklist(checklist)
        version_trove_classifier_updates = (
            "- [ ] Change version in `django/__init__.py` and maybe trove classifier:\n"
            '    - `VERSION = (5, 2, 0, "final", 0)`\n'
            '    - Ensure the "Development Status" trove classifier in '
            "`pyproject.toml` is: `Development Status :: 5 - Production/Stable`\n"
            "    - `git commit -a -m '[5.2.x] Bumped version for 5.2 release.'`\n"
        )
        post_release_bump = (
            "- [ ] BUMP **MINOR VERSION** in `django/__init__.py`\n"
            '    - `VERSION = (5, 2, 1, "alpha", 0)`\n'
            "    - `git commit -a -m '[5.2.x] Post-release version bump.'`"
        )
        feature_release_tasks = [
            "- Remove the `UNDER DEVELOPMENT` header at the top of the release notes",
            "- Remove the `Expected` prefix and update the release date if necessary",
            "- [ ] Create a new branch from the current stable branch in the "
            "[django-docs-translations repository]",
            "- [ ] Update the metadata for the docs in "
            "https://www.djangoproject.com/admin/docs/documentrelease/",
            "- Create new `DocumentRelease` objects for each language",
            "- [ ] Update djangoproject.com's [robots.docs.txt]",
            "- [ ] Update the current stable branch and remove the pre-release branch",
            "- [ ] Update the download page on djangoproject.com.",
            version_trove_classifier_updates,
            post_release_bump,
        ]
        for feature_release_task in feature_release_tasks:
            with self.subTest(task=feature_release_task):
                self.assertIn(feature_release_task, checklist_content)

        with self.subTest(task="Stub release notes added"):
            self.assertStubReleaseNotesAdded(release, checklist_content)

        with self.subTest(task="Make release public steps added"):
            self.assertMakeReleasePublicAdded(release, checklist_content)

        with self.subTest(task="Push and announce steps added"):
            self.assertPushAndAnnouncesAdded(checklist, checklist_content)

        with self.subTest(taks="Blogpost EOM and EOL Release"):
            self.assertIn(
                "With the release of Django 5.2, Django 5.1\nhas reached the "
                "end of mainstream support.",
                checklist_content,
            )
            self.assertIn(
                "Django 5.0 has reached the end of extended support.", checklist_content
            )
