from datetime import date, timedelta

from django.contrib.auth.models import User
from django.test import RequestFactory, TestCase, override_settings

from .admin import render_checklist
from .models import Release, Releaser, SecurityIssue, SecurityRelease


class BaseChecklistTestCaseMixin:

    checklist_class = None
    request_factory = RequestFactory()

    def make_releaser(self):
        return Releaser.objects.create(
            user=User.objects.create(username="releaser"),
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
    def test_render_checklist(self):
        releaser = self.make_releaser()
        future = date.today() + timedelta(days=10)
        instance = self.make_checklist(releaser=releaser, when=future)
        request = self.request_factory.get("/")

        result = render_checklist(request, self.checklist_class.objects.all())

        self.assertNotIn("INVALID", result)


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
