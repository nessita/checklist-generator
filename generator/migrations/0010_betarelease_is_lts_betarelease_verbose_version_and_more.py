# Generated by Django 5.2.dev20240723185001 on 2024-07-24 14:54

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        (
            "generator",
            "0009_featurerelease_created_at_featurerelease_updated_at_and_more",
        ),
    ]

    operations = [
        migrations.AddField(
            model_name="betarelease",
            name="is_lts",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="betarelease",
            name="verbose_version",
            field=models.CharField(default="0.0", max_length=100),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name="betarelease",
            name="version",
            field=models.CharField(default="0.0", max_length=10),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name="featurerelease",
            name="verbose_version",
            field=models.CharField(default="1.1", max_length=100),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name="releasecandidaterelease",
            name="is_lts",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="releasecandidaterelease",
            name="verbose_version",
            field=models.CharField(default="1.1", max_length=100),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name="releasecandidaterelease",
            name="version",
            field=models.CharField(default="2.2", max_length=10),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name="securityrelease",
            name="is_lts",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="securityrelease",
            name="verbose_version",
            field=models.CharField(default="2.2", max_length=100),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name="securityrelease",
            name="version",
            field=models.CharField(default="", max_length=10),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name="featurerelease",
            name="forum_post",
            field=models.URLField(blank=True),
        ),
        migrations.AlterField(
            model_name="featurerelease",
            name="tagline",
            field=models.CharField(
                help_text="Filler to use in the sentence <i>Django [version] brings [tagline] which you can read about in the release notes.</i></br>For example: <i>Django 5.1 brings <strong>a kaleidoscope of improvements</strong></i>.",
                max_length=4096,
            ),
        ),
    ]
