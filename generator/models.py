import datetime
from functools import total_ordering

from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.db import models
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


class ReleaseManager(models.Manager):
    def published(self, at=None):
        """
        List of published releases at a given date (today by default).

        A published release has a suitable publication date and is active.

        The resulting queryset is sorted by decreasing version number.

        This is expected to return the latest micro-release in each series.
        """
        if at is None:
            at = datetime.date.today()
        # .filter(date__lte=at) excludes releases where date IS NULL because
        # a version without a date is considered unreleased.
        # .exclude(eol_date__lte=at) includes releases where eol_date IS NULL
        # because a version without an end of life date is still supported.
        return (
            self.filter(major__gte=1, date__lte=at, is_active=True)
            .exclude(eol_date__lte=at)
            .order_by("-major", "-minor", "-micro", "-status")
        )

    def supported(self, at=None):
        """
        List of supported final releases.
        """
        return self.published(at).filter(status="f")

    def unsupported(self, at=None):
        """
        List of unsupported final releases at a given date (today by default).

        This returns a list, not a queryset, because it requires logic that is
        hard to express in SQL.

        Pre-1.0 releases are ignored.
        """
        if at is None:
            at = datetime.date.today()
        excluded_major_minor = {
            (release.major, release.minor) for release in self.supported(at)
        }
        unsupported = []
        for release in self.filter(major__gte=1, eol_date__lte=at, status="f").order_by(
            "-major", "-minor", "-micro"
        ):
            if (release.major, release.minor) not in excluded_major_minor:
                excluded_major_minor.add((release.major, release.minor))
                unsupported.append(release)
        return unsupported

    def current(self, at=None):
        """
        Current release.
        """
        return self.supported(at).first()

    def previous(self, at=None):
        """
        Previous release.
        """
        return self.supported(at)[1:].first()

    def lts(self, at=None):
        """
        List of supported LTS releases.
        """
        return self.supported(at).filter(is_lts=True)

    def current_lts(self, at=None):
        """
        Current LTS release.
        """
        return self.lts(at).first()

    def previous_lts(self, at=None):
        """
        Previous LTS release or None if there's only one LTS release currently.
        """
        return self.lts(at)[1:].first()

    def preview(self, at=None):
        """
        Preview release or None if there isn't a preview release currently.
        """
        return self.published(at).exclude(status="f").first()


@total_ordering
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
    is_active = models.BooleanField(
        help_text=(
            "Set this release as active. A release is considered active only "
            "if its date is today or in the past and this flag is enabled. "
            "Enable this flag when the release is available on PyPI."
        ),
        default=False,
    )
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
        help_text=(
            'Is this a release for an <abbr title="Long Term Support">LTS</abbr> Django '
            "version (e.g. 5.2a1, 5.2, 5.2.4)?"
        ),
        default=False,
    )
    # Artifacts.
    tarball = models.FileField("Tarball artifact as a .tar.gz file", blank=True)
    wheel = models.FileField("Wheel artifact as a .whl file", blank=True)
    checksum = models.FileField("Signed checksum as a .asc file", blank=True)

    objects = ReleaseManager()

    def save(self, *args, **kwargs):
        self.major, self.minor, self.micro, status, self.iteration = self.version_tuple
        self.status = self.STATUS_REVERSE[status]
        super().save(*args, **kwargs)
        # Each micro release EOLs the previous one in the same series.
        if self.status == "f" and self.micro > 0 and self.is_active:
            (
                type(self)
                .objects.filter(
                    major=self.major, minor=self.minor, micro=self.micro - 1, status="f"
                )
                .update(eol_date=self.date)
            )

    # def __eq__(self, other):
    #     return self.version == other.version

    def __lt__(self, other):
        return (self.major, self.minor, self.micro) < (
            other.major,
            other.minor,
            other.micro,
        )

    def __hash__(self):
        return hash((self.major, self.minor, self.micro))

    def __str__(self):
        return self.version

    @property
    def is_published(self):
        return (
            self.is_active
            and self.date is not None
            and self.date <= datetime.date.today()
        )

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
    def stable_branch(self):
        return f"stable/{self.feature_version}.x"

    @cached_property
    def commit_prefix(self):
        return f"[{self.feature_version}.x]"

    @cached_property
    def is_pre_release(self):
        return self.status != "f"

    def clean(self):
        if self.is_published and not self.tarball:
            raise ValidationError(
                {"tarball": "This field is required when the release is active."}
            )

        if (self.tarball or self.wheel) and not self.checksum:
            raise ValidationError(
                {
                    "checksum": (
                        "This field is required when an artifact has been uploaded."
                    )
                }
            )


class Releaser(models.Model):
    # Eventually a djangoproject.com User.
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    key_id = models.CharField(max_length=100)
    key_url = models.URLField()

    def __str__(self):
        return f"{self.key_id} <{self.key_url}>"


class ReleaseChecklist(models.Model):
    when = models.DateTimeField()
    releaser = models.ForeignKey(Releaser, null=True, on_delete=models.SET_NULL)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    checklist_template = "generator/release-skeleton.md"
    release_status_code = {v: k for k, v in Release.STATUS_REVERSE.items()}

    class Meta:
        abstract = True

    @cached_property
    def blogpost_link(self, slug=None):
        if slug is None:
            slug = self.slug
        when = self.when.strftime("%Y/%b/%d").lower()
        return f"https://www.djangoproject.com/weblog/{when}/{slug}/"

    @cached_property
    def blogpost_template(self):
        return f"generator/release_{self.status}_blogpost.rst"

    @cached_property
    def blogpost_summary(self):
        return f"Django {self.version} has been released!"

    @cached_property
    def previous_status(self):
        result = None
        if self.status == "beta":
            result = "alpha"
        elif self.status == "rc":
            result = "beta"
        elif self.status == "final":
            result = "rc"
        return result

    @cached_property
    def status(self):
        if (release := getattr(self, "release", None)) is not None:
            return self.release_status_code[release.status]
        return ""

    @cached_property
    def trove_classifier(self):
        result = "Development Status :: 5 - Production/Stable"
        if self.status == "alpha":
            result = "Development Status :: 3 - Alpha"
        elif self.status in ("beta", "rc"):
            result = "Development Status :: 4 - Beta"
        return result

    @cached_property
    def version(self):
        if (release := getattr(self, "release", None)) is not None:
            return release.version
        return "many"


class FeatureRelease(ReleaseChecklist):
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
    highlights = models.TextField(blank=True)
    eom_release = models.ForeignKey(
        Release, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    eol_release = models.ForeignKey(
        Release, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )

    def __str__(self):
        return f"{self.version} {self.tagline}"

    @property
    def slug(self):
        return f"django-{self.version.replace('.', '')}-released"


class PreRelease(ReleaseChecklist):
    release = models.OneToOneField(Release, null=True, on_delete=models.SET_NULL)
    feature_release = models.ForeignKey(FeatureRelease, on_delete=models.CASCADE)
    verbose_version = models.CharField(max_length=100)

    @cached_property
    def blogpost_summary(self):
        return (
            f"Today Django {self.verbose_version}, a preview/testing package for the "
            f"upcoming Django {self.final_version} release, is available."
        )

    @cached_property
    def final_version(self):
        return self.feature_release.version

    @cached_property
    def forum_post(self):
        return self.feature_release.forum_post

    @cached_property
    def slug(self):
        return f"django-{self.final_version.replace('.', '')}-{self.status}-released"


class BugFixRelease(ReleaseChecklist):
    release = models.OneToOneField(Release, null=True, on_delete=models.SET_NULL)
    feature_release = models.ForeignKey(FeatureRelease, on_delete=models.CASCADE)

    slug = "bugfix-releases"


class SecurityRelease(ReleaseChecklist):
    checklist_template = "generator/release-security-skeleton.md"
    slug = "security-releases"

    def __str__(self):
        return f"Security release on {self.when}"

    @cached_property
    def cves(self):
        return [cve for cve in self.securityissue_set.all().order_by("cve_year_number")]

    @cached_property
    def affected_branches(self):
        return ["main"] + [
            (
                r.feature_version
                if not r.is_pre_release
                else f"{r.feature_version} (currently at {r.get_status_display()} status)"
            )
            for r in self.affected_releases
        ]

    @cached_property
    def affected_releases(self):
        return sorted(
            {r for issue in self.securityissue_set.all() for r in issue.releases.all()},
            reverse=True,
        )

    @cached_property
    def version(self):
        return " / ".join(self.versions)

    @cached_property
    def versions(self):
        return [r.version for r in self.affected_releases if not r.is_pre_release]

    @cached_property
    def latest_release(self):
        return [r for r in self.affected_releases if not r.is_pre_release][0]

    @cached_property
    def hashes_by_versions(self):
        return [
            {
                "branch": sirt.release.feature_version,
                "cve": sirt.securityissue.cve_year_number,
                "hash": sirt.commit_hash,
            }
            for sirt in SecurityIssueReleasesThrough.objects.select_related(
                "securityissue", "release"
            )
            .filter(securityissue__release_id=self.id)
            .order_by("release__version")
        ] + [
            {
                "branch": "main",
                "cve": issue.cve_year_number,
                "hash": issue.commit_hash_main,
            }
            for issue in self.securityissue_set.all()
        ]


class SecurityIssueReleasesThrough(models.Model):
    securityissue = models.ForeignKey("SecurityIssue", on_delete=models.CASCADE)
    release = models.ForeignKey(Release, on_delete=models.CASCADE)
    commit_hash = models.CharField(
        max_length=128, default="", blank=True, db_index=True
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["securityissue", "release"],
                name="unique_securityissue_release",
            ),
            models.UniqueConstraint(
                fields=["commit_hash"],
                name="unique_non_empty_commit_hash",
                condition=~models.Q(commit_hash=""),  # Exclude empty strings
            ),
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
        max_length=128,
        choices=[(i, i.capitalize()) for i in ("low", "moderate", "high")],
        default="moderate",
    )
    summary = models.CharField(max_length=1024)
    description = models.TextField(help_text=DESCRIPTION_HELP_TEXT)
    blogdescription = models.TextField(blank=True)

    reporter = models.CharField(max_length=1024, blank=True)
    release = models.ForeignKey(
        SecurityRelease,
        help_text="Security Release that will fix this issue.",
        on_delete=models.CASCADE,
    )
    releases = models.ManyToManyField(Release, through=SecurityIssueReleasesThrough)
    commit_hash_main = models.CharField(
        max_length=128, default="", blank=True, db_index=True
    )

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
        return sorted(
            [
                (sirt.release.feature_version, sirt.commit_hash)
                for sirt in SecurityIssueReleasesThrough.objects.select_related(
                    "release"
                ).filter(securityissue_id=self.id)
            ]
            + [("main", self.commit_hash_main)],
            reverse=True,
        )

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
