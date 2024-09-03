from django.contrib.postgres.fields import ArrayField
from django.core.exceptions import ValidationError
from django.db import models


CVE_TYPE_OTHER = "Other or Unknown"
CVE_TYPE = [
    "Buffer Overflow",
    "Cross Site Request Forgery (CSRF)",
    "Cross Site Scripting (XSS)",
    "Directory Traversal",
    "Incorrect Access Control",
    "Insecure Permissions",
    "Integer Overflow",
    "Missing SSL Certificate Validation",
    "SQL Injection",
    "XML External Entity (XXE)",
    CVE_TYPE_OTHER,
]
CVE_OTHER_TYPE = [
    "Algorithm complexity",
    "Array index error",
    "Auth bypass using cookie",
    "Buffer Overflow",
    "Cross-Site Request Forgery (CSRF)",
    "Cross-Site Scripting (XSS)",
    "Directory Traversal",
    "Double free",
    "Eval injection",
    "File Upload",
    "Format String",
    "HTTP Response Splitting",
    "HTTP Request Splitting",
    "Incomplete blacklist",
    "Integer Overflow",
    "Integer Signedness",
    "Memory Leak",
    "Shell Metacharacter Injection",
    "Open Redirect",
    "Redirect without Exit",
    "Path Disclosure",
    "Insecure Permissions",
    "PHP remote file inclusion",
    "Session Fixation",
    "SQL Injection",
    "Symbolic Link Following",
    "Untrusted Search Path",
    "Unquoted Windows search path",
    "Use after free",
    "Default user/password",
    "Large or infinite loop",
    "Exposed insecure/unsafe method in ActiveX control",
    "Generation of insufficiently random numbers",
    "XML Extneral Entity (XXE)",
    "Incorrect Access Control",
    "Missing SSL certificate validation",
]

ATTACK_TYPE = [
    "Context-dependent",
    "Local",
    "Physical",
    "Remote",
    "Other",
]
IMPACT_TYPE = [
    "Code Execution",
    "Denial of Service",
    "Escalation of Privileges",
    "Information Disclosure",
    "Other",
]
DESCRIPTION_HELP_TEXT = """Written in present tense.
==> Do not include versions, these will be prepended automatically. <==

CVE documented format suggestions:

<pre>
    •[VULNTYPE] in [COMPONENT] in [VENDOR] [PRODUCT] [VERSION] allows
    [ATTACKER] to [IMPACT] via [VECTOR].

    •[COMPONENT] in [VENDOR] [PRODUCT] [VERSION] [ROOT CAUSE], which allows
    [ATTACKER] to [IMPACT] via [VECTOR]
</pre>

Examples:
<pre>
    The password hasher in contrib/auth/hashers.py allows remote attackers to
    enumerate users via a timing attack involving login requests.

    The intcomma template filter is subject to a potential denial-of-service
    attack when used with very long strings.

    The django.contrib.auth.forms.UsernameField is subject to a potential
    denial-of-service attack via certain inputs with a very large number of
    Unicode characters (because the NFKC normalization is slow on Windows).
</pre>
"""

class Release(models.Model):
    version = models.CharField(max_length=10)
    is_lts = models.BooleanField(default=False)

    when = models.DateTimeField()
    who = models.CharField(max_length=1024)
    who_key_id = models.CharField(max_length=100)
    who_key_url = models.URLField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    checklist_template = None

    class Meta:
        abstract = True

    def get_context_data(self):
        return {"release": self, "title": self._meta.verbose_name.title()}

    def blogpost_link(self, slug=None):
        if slug is None:
            slug = self.slug
        when = self.when.strftime("%Y/%m/%d")
        print("\n\n\n\n=========== returning: " + f"https://www.djangoproject.com/weblog/{when}/{slug}/")
        return f"https://www.djangoproject.com/weblog/{when}/{slug}/"


class FeatureRelease(Release):
    forum_post = models.URLField(blank=True)
    tagline = models.CharField(
        max_length=4096,
        help_text=(
            "Filler to use in the sentence <i>Django [version] brings "
            "[tagline] which you can read about in the release notes.</i></br>"
            "For example: <i>Django 5.1 brings <strong>a kaleidoscope of "
            "improvements</strong></i>."),
    )

    def __str__(self):
        return f"{self.version} {self.tagline}"

    @property
    def slug(self):
        return f"django-{self.final_version.replace('.', '')}-released"


class PreRelease(Release):
    feature_release = models.ForeignKey(FeatureRelease, on_delete=models.CASCADE)
    verbose_version = models.CharField(max_length=100)

    class Meta:
        abstract = True

    def final_version(self):
        return self.feature_release.version

    def get_context_data(self):
        return super().get_context_data() | {"feature_release": self.feature_release}


class AlphaRelease(PreRelease):
    checklist_template = "generator/release-alpha-skeleton.md"

    @property
    def slug(self):
        return f"django-{self.final_version.replace('.', '')}-alpha-released"


class BetaRelease(PreRelease):
    checklist_template = "generator/release-beta-skeleton.md"

    @property
    def slug(self):
        return f"django-{self.final_version.replace('.', '')}-beta-released"


class ReleaseCandidateRelease(PreRelease):
    checklist_template = "generator/release-rc-skeleton.md"

    @property
    def slug(self):
        return f"django-{self.final_version.replace('.', '')}-rc1"


class BugFixRelease(Release):
    feature_release = models.ForeignKey(FeatureRelease, on_delete=models.CASCADE)

    slug = "bugfix-releases"


class SecurityRelease(Release):
    versions = ArrayField(models.CharField(max_length=100))
    affected_branches = ArrayField(models.CharField(max_length=100))
    # A ManyToMany between versions and hashes fixing a given issue in a given
    # affected branch.
    # hashes = ArrayField(models.CharField(max_length=100))

    checklist_template = "generator/release-security-skeleton.md"
    slug = "security-releases"

    def __str__(self):
        return f"Security release for {self.versions}"

    def get_context_data(self):
        return super().get_context_data() | {"cves": [
            cve.__dict__
            for cve in self.securityissue_set.all().order_by("cve_year_number")
        ]}


class SecurityIssue(models.Model):
    cve_year_number = models.CharField(max_length=1024, unique=True)
    cve_type = models.CharField(
        max_length=1024, choices=[(i, i) for i in CVE_TYPE], default=CVE_TYPE_OTHER)
    other_type = models.CharField(
        max_length=1024, default="DoS", blank=True)
    attack_type = models.CharField(
        max_length=1024, choices=[(i, i) for i in ATTACK_TYPE], default="Remote")
    impact = models.CharField(
        max_length=1024, choices=[(i, i) for i in IMPACT_TYPE], default="Denial of Service")
    severity = models.CharField(
        choices=[(i, i.capitalize()) for i in ("low", "moderate", "high")],
        default="moderate",
    )
    summary = models.CharField(max_length=1024)
    description = models.TextField(help_text=DESCRIPTION_HELP_TEXT)

    reporter = models.CharField(max_length=1024, blank=True)
    release = models.ForeignKey(SecurityRelease, on_delete=models.CASCADE)

    def clean_fields(self, *args, **kwargs):
        if self.cve_type == CVE_TYPE_OTHER and not self.other_type:
            raise ValidationError(
                '"Other type" needs to be set when "Vulnerability type" is ' +
                CVE_TYPE_OTHER
            )
        if self.cve_type != CVE_TYPE_OTHER and self.other_type:
            raise ValidationError(f'"Other type" should be blank for "{self.cve_type}".')
