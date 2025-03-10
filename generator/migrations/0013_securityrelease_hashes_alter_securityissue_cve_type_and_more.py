# Generated by Django 5.2.dev20240903105106 on 2024-09-03 16:57

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("generator", "0012_remove_bugfixrelease_verbose_version_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="securityrelease",
            name="hashes",
            field=models.JSONField(default={}),
        ),
        migrations.AlterField(
            model_name="securityissue",
            name="cve_type",
            field=models.CharField(
                choices=[
                    ("Buffer Overflow", "Buffer Overflow"),
                    (
                        "Cross Site Request Forgery (CSRF)",
                        "Cross Site Request Forgery (CSRF)",
                    ),
                    ("Cross Site Scripting (XSS)", "Cross Site Scripting (XSS)"),
                    ("Directory Traversal", "Directory Traversal"),
                    ("Incorrect Access Control", "Incorrect Access Control"),
                    ("Insecure Permissions", "Insecure Permissions"),
                    ("Integer Overflow", "Integer Overflow"),
                    (
                        "Missing SSL Certificate Validation",
                        "Missing SSL Certificate Validation",
                    ),
                    ("SQL Injection", "SQL Injection"),
                    ("XML External Entity (XXE)", "XML External Entity (XXE)"),
                    ("Other or Unknown", "Other or Unknown"),
                ],
                default="Other or Unknown",
                max_length=1024,
            ),
        ),
        migrations.AlterField(
            model_name="securityissue",
            name="description",
            field=models.TextField(
                help_text="Written in present tense.\n==> Do not include versions, these will be prepended automatically. <==\n\nCVE documented format suggestions:\n\n<pre>\n    •[VULNTYPE] in [COMPONENT] in [VENDOR] [PRODUCT] [VERSION] allows\n    [ATTACKER] to [IMPACT] via [VECTOR].\n\n    •[COMPONENT] in [VENDOR] [PRODUCT] [VERSION] [ROOT CAUSE], which allows\n    [ATTACKER] to [IMPACT] via [VECTOR]\n</pre>\n\nExamples:\n<pre>\n    The password hasher in contrib/auth/hashers.py allows remote attackers to\n    enumerate users via a timing attack involving login requests.\n\n    The intcomma template filter is subject to a potential denial-of-service\n    attack when used with very long strings.\n\n    The django.contrib.auth.forms.UsernameField is subject to a potential\n    denial-of-service attack via certain inputs with a very large number of\n    Unicode characters (because the NFKC normalization is slow on Windows).\n</pre>\n"
            ),
        ),
        migrations.AlterField(
            model_name="securityissue",
            name="impact",
            field=models.CharField(
                choices=[
                    ("Code Execution", "Code Execution"),
                    ("Denial of Service", "Denial of Service"),
                    ("Escalation of Privileges", "Escalation of Privileges"),
                    ("Information Disclosure", "Information Disclosure"),
                    ("Other", "Other"),
                ],
                default="Denial of Service",
                max_length=1024,
            ),
        ),
        migrations.AlterField(
            model_name="securityissue",
            name="other_type",
            field=models.CharField(blank=True, default="DoS", max_length=1024),
        ),
        migrations.AlterField(
            model_name="securityissue",
            name="severity",
            field=models.CharField(
                choices=[("low", "Low"), ("moderate", "Moderate"), ("high", "High")],
                default="moderate",
            ),
        ),
    ]
