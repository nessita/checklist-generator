# Generated by Django 5.2.dev20240723185001 on 2024-07-24 12:39

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("generator", "0007_releasecandidaterelease"),
    ]

    operations = [
        migrations.RenameField(
            model_name="securityrelease",
            old_name="releases",
            new_name="versions",
        ),
        migrations.AddField(
            model_name="featurerelease",
            name="is_lts",
            field=models.BooleanField(default=False),
        ),
    ]
