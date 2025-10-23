from django.test import TestCase
from django.urls import reverse

from generator.tests.factory import Factory


class SecurityReleaseChecklistViewTestCase(TestCase):
    factory = Factory()

    def url(self, checklist):
        return reverse("generator:securityrelease_checklist", args=[checklist.pk])

    def test_requires_login_and_permissions(self):
        checklist = self.factory.make_security_checklist()
        url = self.url(checklist)

        # Anonymous user is redirected to login.
        response = self.client.get(url)
        self.assertRedirects(
            response, f"/accounts/login/?next={url}", fetch_redirect_response=False
        )

        # Authenticated without perms gets forbidden.
        user = self.factory.make_user()
        assert self.client.login(username=user.username, password=user.raw_password)
        with self.assertLogs("django.request", level="WARNING"):
            response = self.client.get(url)
        self.assertEqual(response.status_code, 403)

        # Authenticated with other perms gets forbidden.
        user = self.factory.make_user(perm_names=["view_securityissue"])
        assert self.client.login(username=user.username, password=user.raw_password)
        with self.assertLogs("django.request", level="WARNING"):
            response = self.client.get(url)
        self.assertEqual(response.status_code, 403)

    def test_with_expected_permissions(self):
        checklist = self.factory.make_security_checklist()

        user = self.factory.make_user(
            perm_names=["view_securityrelease", "view_securityissue"]
        )
        assert self.client.login(username=user.username, password=user.raw_password)

        response = self.client.get(self.url(checklist))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "<h1>Django Security Release")


class SecurityIssueViewTestCase(TestCase):
    factory = Factory()

    def url(self, issue):
        return reverse("generator:cve_json_record", args=[issue.cve_year_number])

    def test_requires_login_and_permissions(self):
        issue = self.factory.make_security_issue()
        url = self.url(issue)

        # Anonymous user is redirected to login.
        response = self.client.get(url)
        self.assertRedirects(
            response, f"/accounts/login/?next={url}", fetch_redirect_response=False
        )

        # Authenticated without perms gets forbidden.
        user = self.factory.make_user()
        assert self.client.login(username=user.username, password=user.raw_password)
        with self.assertLogs("django.request", level="WARNING"):
            response = self.client.get(url)
        self.assertEqual(response.status_code, 403)

        # Authenticated with other perms gets forbidden.
        user = self.factory.make_user(perm_names=["view_securityrelease"])
        assert self.client.login(username=user.username, password=user.raw_password)
        with self.assertLogs("django.request", level="WARNING"):
            response = self.client.get(url)
        self.assertEqual(response.status_code, 403)

    def test_with_permissions(self):
        issue = self.factory.make_security_issue()

        user = self.factory.make_user(perm_names=["view_securityissue"])
        assert self.client.login(username=user.username, password=user.raw_password)

        response = self.client.get(self.url(issue))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/json")
        data = response.json()
        self.assertEqual(data, issue.cve_data)
