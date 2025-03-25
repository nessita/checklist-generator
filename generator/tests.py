from datetime import date, timedelta
from uuid import uuid4

from django.contrib.auth.models import User
from django.test import RequestFactory, TestCase, override_settings
from django.utils.timezone import now

from .admin import render_checklist
from .models import (
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

    def make_security_issue(self, security_release_checklist, releases=None, **kwargs):
        issue = SecurityIssue.objects.create(
            release=security_release_checklist, **kwargs
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
