import datetime

from django.contrib.auth.models import User
from django.contrib.postgres.fields import ArrayField
from django.core.exceptions import ValidationError
from django.db import models
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils.functional import cached_property

from .utils import get_loose_version_tuple

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


class Release(models.Model):  # This is the exact model from djangoproject.com
    STATUS_CHOICES = (
        ("a", "alpha"),
        ("b", "beta"),
        ("c", "release candidate"),
        ("f", "final"),
    )
    STATUS_REVERSE = {
        "alpha": "a",
        "beta": "b",
        "rc": "c",
        "final": "f",
    }

    version = models.CharField(max_length=16, primary_key=True)
    date = models.DateField(
        "Release date",
        null=True,
        blank=True,
        default=datetime.date.today,
        help_text="Leave blank if the release date isn't know yet, typically "
        "if you're creating the final release just after the alpha "
        "because you want to build docs for the upcoming version.",
    )
    eol_date = models.DateField(
        "End of life date",
        null=True,
        blank=True,
        help_text="Leave blank if the end of life date isn't known yet, "
        "typically because it depends on the release date of a "
        "later version.",
    )

    major = models.PositiveSmallIntegerField(editable=False)
    minor = models.PositiveSmallIntegerField(editable=False)
    micro = models.PositiveSmallIntegerField(editable=False)
    status = models.CharField(max_length=1, choices=STATUS_CHOICES, editable=False)
    iteration = models.PositiveSmallIntegerField(editable=False)
    is_lts = models.BooleanField(
        "Long Term Support",
        help_text='Is this an (<abbr title="Long Term Support">LTS</abbr>) release?',
        default=False,
    )

    def save(self, *args, **kwargs):
        self.major, self.minor, self.micro, status, self.iteration = self.version_tuple
        self.status = self.STATUS_REVERSE[status]
        super().save(*args, **kwargs)
        # Each micro release EOLs the previous one in the same series.
        if self.status == "f" and self.micro > 0:
            (
                type(self)
                .objects.filter(
                    major=self.major, minor=self.minor, micro=self.micro - 1, status="f"
                )
                .update(eol_date=self.date)
            )

    def __str__(self):
        return self.version

    @cached_property
    def version_tuple(self):
        """Return a tuple in the format of django.VERSION."""
        version = self.version.replace("-", "").replace("_", "")
        version = list(get_loose_version_tuple(version))
        if len(version) == 2:
            version.append(0)
        if not isinstance(version[2], int):
            version.insert(2, 0)
        if len(version) == 3:
            version.append("final")
        if version[3] not in ("alpha", "beta", "rc", "final"):
            version[3] = {"a": "alpha", "b": "beta", "c": "rc"}[version[3]]
        if len(version) == 4:
            version.append(0)
        return tuple(version)

    @cached_property
    def feature_version(self):
        return f"{self.major}.{self.minor}"

    @cached_property
    def series(self):
        return f"{self.major}.x"

    @cached_property
    def is_pre_release(self):
        return self.status != "f"


class Releaser(models.Model):
    # Eventually a djangoproject.com User.
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    key_id = models.CharField(max_length=100)
    key_url = models.URLField()

    def __str__(self):
        return f"{self.key_id} <{self.key_url}>"


class ReleaseEvent:

    checklist_template = None

    @cached_property
    def version(self):
        if (release := getattr(self, "release", None)) is not None:
            return release.version
        return "many"

    def get_context_data(self):
        return {"release": self, "title": self.__class__.__name__}

    def blogpost_link(self, slug=None):
        if slug is None:
            slug = self.slug
        when = self.when.strftime("%Y/%b/%d").lower()
        return f"https://www.djangoproject.com/weblog/{when}/{slug}/"


class FeatureRelease(ReleaseEvent, models.Model):
    when = models.DateTimeField()
    releaser = models.ForeignKey(Releaser, null=True, on_delete=models.SET_NULL)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    release = models.OneToOneField(Release, null=True, on_delete=models.SET_NULL)
    forum_post = models.URLField(blank=True)
    tagline = models.CharField(
        max_length=4096,
        help_text=(
            "Filler to use in the sentence <i>Django [version] brings "
            "[tagline] which you can read about in the release notes.</i></br>"
            "For example: <i>Django 5.1 brings <strong>a kaleidoscope of "
            "improvements</strong></i>."
        ),
    )

    def __str__(self):
        return f"{self.version} {self.tagline}"

    @property
    def slug(self):
        return f"django-{self.final_version.replace('.', '')}-released"


class PreRelease(ReleaseEvent, models.Model):
    when = models.DateTimeField()
    releaser = models.ForeignKey(Releaser, null=True, on_delete=models.SET_NULL)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    release = models.OneToOneField(Release, null=True, on_delete=models.SET_NULL)
    feature_release = models.ForeignKey(FeatureRelease, on_delete=models.CASCADE)
    verbose_version = models.CharField(max_length=100)

    class Meta:
        abstract = True

    @cached_property
    def checklist_template(self):
        return f"generator/release-{self.status}-skeleton.md"

    @cached_property
    def final_version(self):
        return self.feature_release.version

    @cached_property
    def slug(self):
        return f"django-{self.final_version.replace('.', '')}-{self.status}-released"

    def get_context_data(self):
        return super().get_context_data() | {"feature_release": self.feature_release}


class AlphaRelease(PreRelease):
    pass


class BetaRelease(PreRelease):
    pass


class ReleaseCandidateRelease(PreRelease):
    pass


class BugFixRelease(ReleaseEvent, models.Model):
    when = models.DateTimeField()
    releaser = models.ForeignKey(Releaser, null=True, on_delete=models.SET_NULL)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    release = models.OneToOneField(Release, null=True, on_delete=models.SET_NULL)
    feature_release = models.ForeignKey(FeatureRelease, on_delete=models.CASCADE)

    slug = "bugfix-releases"


class SecurityRelease(ReleaseEvent, models.Model):
    when = models.DateTimeField()
    releaser = models.ForeignKey(Releaser, null=True, on_delete=models.SET_NULL)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    versions = ArrayField(models.CharField(max_length=100, null=True))
    affected_branches = ArrayField(models.CharField(max_length=100, null=True))
    # A mapping between CVEs and affected branches, each one contaning the
    # hashes fixing the issue.
    hashes = models.JSONField(default=dict, blank=True)

    checklist_template = "generator/release-security-skeleton.md"
    slug = "security-releases"

    def __str__(self):
        return f"Security release on {self.when}"

    @cached_property
    def version(self):
        return " / ".join(self.versions)

    @cached_property
    def newversions(self):
        return sorted(
            {
                r.version
                for issue in self.securityissue_set.all()
                for r in issue.releases.all()
            }
        )

    @cached_property
    def newaffected_branches(self):
        releases = {
            r.feature_version
            for issue in self.securityissue_set.all()
            for r in issue.releases.all()
        }
        return ["main", *sorted(releases, reverse=True)]

    @property
    def hashes_by_versions(self):
        return [
            {"branch": branch, "cve": cve, "hash": h}
            for cve, hashes in self.hashes.items()
            for branch, h in hashes.items()
        ]

    def get_context_data(self):
        extra = {
            "cves": [
                cve for cve in self.securityissue_set.all().order_by("cve_year_number")
            ],
            "hashes_by_versions": self.hashes_by_versions,
        }
        import pprint

        pprint.pprint(extra)
        return super().get_context_data() | extra

    def populate_hashes(self, cve, overwrite=False, commit=True):
        cve_key = cve.cve_year_number
        if cve_key not in self.hashes or overwrite:
            self.hashes[cve_key] = {i: None for i in self.affected_branches}
            if commit:
                self.save(update_fields={"hashes"})
                return True
        return False


class SecurityIssueReleasesThrough(models.Model):
    securityissue = models.ForeignKey("SecurityIssue", on_delete=models.CASCADE)
    release = models.ForeignKey(Release, on_delete=models.CASCADE)
    commit_hash = models.CharField(max_length=128, default="", blank=True, db_index=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["securityissue", "release"],
                name="unique_securityissue_release",
            ),
            models.UniqueConstraint(
                fields=["commit_hash"],
                name='unique_non_empty_commit_hash',
                condition=~models.Q(commit_hash=""),  # Exclude empty strings
            )
        ]


class SecurityIssue(models.Model):
    cve_year_number = models.CharField(max_length=1024, unique=True)
    cve_type = models.CharField(
        max_length=1024, choices=[(i, i) for i in CVE_TYPE], default=CVE_TYPE_OTHER
    )
    other_type = models.CharField(max_length=1024, default="DoS", blank=True)
    attack_type = models.CharField(
        max_length=1024, choices=[(i, i) for i in ATTACK_TYPE], default="Remote"
    )
    impact = models.CharField(
        max_length=1024,
        choices=[(i, i) for i in IMPACT_TYPE],
        default="Denial of Service",
    )
    severity = models.CharField(
        choices=[(i, i.capitalize()) for i in ("low", "moderate", "high")],
        default="moderate",
    )
    summary = models.CharField(max_length=1024)
    description = models.TextField(help_text=DESCRIPTION_HELP_TEXT)
    blogdescription = models.TextField()

    reporter = models.CharField(max_length=1024, blank=True)
    release = models.ForeignKey(SecurityRelease, on_delete=models.CASCADE)
    releases = models.ManyToManyField(Release, through=SecurityIssueReleasesThrough)
    commit_hash_main = models.CharField(max_length=128, default="", blank=True, db_index=True)

    def __str__(self):
        return f"Security issue for {self.cve_year_number}"

    @property
    def headline_for_blogpost(self):
        return f"{self.cve_year_number}: {self.summary}"

    @property
    def headline_for_archive(self):
        when = self.release.when.strftime("%B %-d, %Y")
        return f"{when} - :cve:`{self.cve_year_number.replace('CVE-', '')}`"

    @property
    def hashes_by_branch(self):
        return reversed(self.release.hashes[self.cve_year_number].items())

    def clean_fields(self, *args, **kwargs):
        if self.cve_type == CVE_TYPE_OTHER and not self.other_type:
            raise ValidationError(
                '"Other type" needs to be set when "Vulnerability type" is '
                + CVE_TYPE_OTHER
            )
        if self.cve_type != CVE_TYPE_OTHER and self.other_type:
            raise ValidationError(
                f'"Other type" should be blank for "{self.cve_type}".'
            )


@receiver(post_save, sender=SecurityIssue)
def populate_release_hashes(sender, instance, created, **kwargs):
    instance.release.populate_hashes(instance, overwrite=created)
