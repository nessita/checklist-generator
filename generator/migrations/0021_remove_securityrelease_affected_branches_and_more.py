# Generated by Django 6.0.dev20250305152038 on 2025-03-07 20:50

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("generator", "0020_securityissue_commit_hash_main_and_more"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="securityrelease",
            name="affected_branches",
        ),
        migrations.RemoveField(
            model_name="securityrelease",
            name="hashes",
        ),
        migrations.RemoveField(
            model_name="securityrelease",
            name="versions",
        ),
    ]
