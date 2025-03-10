# Generated by Django 6.0.dev20250305152038 on 2025-03-06 13:58

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("generator", "0015_securityissue_blogdescription_and_more"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="Releaser",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("key_id", models.CharField(max_length=100)),
                ("key_url", models.URLField()),
                (
                    "user",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
        ),
        migrations.AddField(
            model_name="alpharelease",
            name="releaser",
            field=models.ForeignKey(
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                to="generator.releaser",
            ),
        ),
        migrations.AddField(
            model_name="betarelease",
            name="releaser",
            field=models.ForeignKey(
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                to="generator.releaser",
            ),
        ),
        migrations.AddField(
            model_name="bugfixrelease",
            name="releaser",
            field=models.ForeignKey(
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                to="generator.releaser",
            ),
        ),
        migrations.AddField(
            model_name="featurerelease",
            name="releaser",
            field=models.ForeignKey(
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                to="generator.releaser",
            ),
        ),
        migrations.AddField(
            model_name="releasecandidaterelease",
            name="releaser",
            field=models.ForeignKey(
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                to="generator.releaser",
            ),
        ),
        migrations.AddField(
            model_name="securityrelease",
            name="releaser",
            field=models.ForeignKey(
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                to="generator.releaser",
            ),
        ),
    ]
