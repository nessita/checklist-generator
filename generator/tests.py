from datetime import date, datetime, timedelta
from uuid import uuid4

from django.contrib.auth.models import User
from django.test import RequestFactory, TestCase, override_settings

from .admin import render_checklist
from .models import Release, Releaser, SecurityIssue, SecurityRelease


class BaseChecklistTestCaseMixin:
    checklist_class = None
    request_factory = RequestFactory()

    def make_releaser(self):
        return Releaser.objects.create(
            user=User.objects.create(username=f"releaser-{uuid4()}"),
            key_id="1234567890ABCDEF",
            key_url="https://github.com/releaser.gpg",
        )

    def make_checklist(self, releaser, when, **kwargs):
        return self.checklist_class.objects.create(
            releaser=releaser, when=when, **kwargs
        )

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
    def do_render_checklist(self, releaser=None, when=None, **checklist_kwargs):
        if releaser is None:
            releaser = self.make_releaser()
        if when is None:
            when = datetime.now() + timedelta(days=10)
        instance = self.make_checklist(releaser=releaser, when=when, **checklist_kwargs)
        request = self.request_factory.get("/")

        response = render_checklist(request, [instance])
        result = response.content.decode("utf-8")
        idx = result.find("INVALID")
        if idx != -1:
            start = max(idx - 10, 0)
            end = min(start + 1000, len(result))
            fragment = result[start:end]
            self.fail(f"'INVALID' unexpectedly found in {fragment}")
        return result

    def test_render_checklist(self):
        self.do_render_checklist()


class SecurityReleaseChecklistTestCase(BaseChecklistTestCaseMixin, TestCase):
    checklist_class = SecurityRelease

    def make_checklist(self, **kwargs):
        checklist = super().make_checklist(**kwargs)
        issue = SecurityIssue.objects.create(release=checklist)
        release = Release.objects.create(
            version="5.2", date=date(2025, 4, 2), is_lts=True
        )
        assert release is not None
        issue.releases.add(release)
        return checklist
