# Generated by Django 6.0.dev20250325152341 on 2025-03-25 19:05

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        (
            "generator",
            "0001_squashed_0026_release_checksum_release_is_active_release_tarball_and_more",
        ),
    ]

    operations = [
        migrations.AlterField(
            model_name="securityissue",
            name="release",
            field=models.ForeignKey(
                blank=True,
                help_text="Security Release that will fix this issue.",
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                to="generator.securityrelease",
            ),
        ),
    ]
