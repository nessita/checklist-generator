import json
import random
from datetime import date, datetime, timedelta
from uuid import uuid4

from django.contrib.auth.models import User
from django.template.defaultfilters import wordwrap
from django.test import RequestFactory, TestCase, override_settings
from django.utils.timezone import make_aware, now

from .admin import render_checklist
from .models import (
    SEVERITY_LEVELS_DOCS,
    FeatureRelease,
    PreRelease,
    Release,
    Releaser,
    SecurityIssue,
    SecurityRelease,
)


class BaseChecklistTestCaseMixin:
    checklist_class = None
    request_factory = RequestFactory()

    def debug_checklist(self, content):
        with open(f"{self.id()}-checklist.md", "w") as f:
            f.write(content)

    def make_releaser(self):
        return Releaser.objects.create(
            user=User.objects.create(username=f"releaser-{uuid4()}"),
            key_id="1234567890ABCDEF",
            key_url="https://github.com/releaser.gpg",
        )

    def make_checklist(self, releaser=None, when=None, **kwargs):
        if releaser is None:
            releaser = self.make_releaser()
        if when is None:
            when = now() + timedelta(days=10)
        return self.checklist_class.objects.create(
            releaser=releaser, when=when, **kwargs
        )

    def assertNotInChecklistContent(self, text, content):
        """Show more readable error message on `assertNotIn` failures."""
        idx = content.find(text)
        if idx != -1:
            start = max(idx - 10, 0)
            end = min(start + 100, len(content))
            fragment = content[start:end]
            self.fail(f"{text!r} unexpectedly found in:\n{fragment}")

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
        response = render_checklist(request, [checklist_instance])
        self.assertEqual(response["Content-Type"], "text/markdown")

        content = response.content.decode("utf-8")
        self.assertNotInChecklistContent("INVALID", content)

        return content


class SecurityReleaseChecklistTestCase(BaseChecklistTestCaseMixin, TestCase):
    checklist_class = SecurityRelease

    def make_security_issue(
        self,
        security_release_checklist,
        releases=None,
        *,
        cve_year_number=None,
        **kwargs,
    ):
        if cve_year_number is None:  # make a random one to avoid collision
            current_year = now().year
            random_5digit = random.randint(10000, 100000)
            cve_year_number = f"CVE-{current_year}-{random_5digit}"

        issue = SecurityIssue.objects.create(
            release=security_release_checklist,
            cve_year_number=cve_year_number,
            **kwargs,
        )
        if releases is None:
            releases = [
                Release.objects.create(
                    version="5.2", date=date(2025, 4, 2), is_lts=True
                )
            ]
        issue.releases.add(*releases)
        return issue

    def make_checklist(self, with_issues=True, **kwargs):
        checklist = super().make_checklist(**kwargs)
        if with_issues:
            self.make_security_issue(checklist)
        return checklist

    def test_render_checklist_simple(self):
        checklist_content = self.do_render_checklist()
        self.assertIn(
            "- [ ] Submit a CVE Request https://cveform.mitre.org for all issues",
            checklist_content,
        )

    def test_render_checklist_affects_prerelease(self):
        releases = [
            Release.objects.create(version="5.0.14", date=date(2025, 4, 2)),
            Release.objects.create(version="5.1.8", date=date(2025, 4, 2)),
            Release.objects.create(version="5.2rc1", date=date(2025, 3, 19)),
        ]
        checklist = self.make_checklist(with_issues=False)
        self.make_security_issue(checklist, releases, cve_year_number="CVE-2025-11111")
        self.make_security_issue(checklist, releases, cve_year_number="CVE-2025-22222")

        checklist_content = self.do_render_checklist(checklist)
        self.debug_checklist(checklist_content)

        self.assertNotInChecklistContent("5.2 before 5.2rc1", checklist_content)
        self.assertIn(
            "- Affected product(s)/code base (SPLIT in product and version (X before Y) "
            "in rows!):",
            checklist_content,
        )
        for release in ("5.1 before 5.1.8", "5.0 before 5.0.14"):
            with self.subTest(release=release):
                expected = f"[row 1] Django\n      [row 2] {release}"
                self.assertIn(expected, checklist_content)

    def test_render_checklist_blogdescription_display(self):
        checklist = self.make_checklist(with_issues=False)
        blog = (
            "This is a blog description that would be used in the Django site "
            '"News" section. The full list of news can be found `in this link '
            "<https://www.djangoproject.com/weblog/>`_."
        )
        self.make_security_issue(checklist, blogdescription=blog)

        checklist_content = self.do_render_checklist(checklist)

        self.assertIn(
            "- [ ] Submit a CVE Request https://cveform.mitre.org for all issues",
            checklist_content,
        )
        self.assertIn(wordwrap(blog, 80), checklist_content)

    def test_render_cve_json(self):
        releases = [
            Release.objects.create(version="5.0.14", date=date(2025, 4, 2)),
            Release.objects.create(version="5.1.8", date=date(2025, 4, 2)),
            Release.objects.create(version="5.2rc1", date=date(2025, 3, 19)),
        ]
        when = datetime(2024, 12, 4, 10)
        checklist = self.make_checklist(
            with_issues=False,
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
        issue = self.make_security_issue(
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
                "value": f"Django would like to thank {reporter} for reporting this issue.",
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

    def make_checklist(self, **kwargs):
        future = now() + timedelta(days=75)
        feature_release = FeatureRelease.objects.create(
            when=future, tagline="collection"
        )
        return super().make_checklist(feature_release=feature_release, **kwargs)

    def test_render_checklist(self):
        status_to_version = {
            "a": "alpha",
            "b": "beta",
            "rc": "release candidate",
        }
        for status, version in status_to_version.items():
            release = Release.objects.create(
                version=f"5.2{status}1", date=date(2025, 4, 2), is_lts=True
            )
            with self.subTest(version=version):
                instance = self.make_checklist(verbose_version=version, release=release)
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
