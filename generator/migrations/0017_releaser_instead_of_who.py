# Generated by Django 6.0.dev20250305152038 on 2025-03-06 13:59

from django.db import migrations


def populate_releasers(apps, schema_editor):
    User = apps.get_model("auth", "User")
    Releaser = apps.get_model("generator", "Releaser")

    sarahboyce = Releaser.objects.create(
        user=User.objects.get(username="sarahboyce"),
        key_id="3955B19851EA96EF",
        key_url="https://github.com/sarahboyce.gpg",
    )
    nessita = Releaser.objects.create(
        user=User.objects.get(username="nessita"),
        key_id="2EE82A8D9470983E",
        key_url="https://github.com/nessita.gpg",
    )
    for model_name in (
        "AlphaRelease",
        "BetaRelease",
        "FeatureRelease",
        "ReleaseCandidateRelease",
        "BugFixRelease",
        "SecurityRelease",
    ):
        model_class = apps.get_model("generator", model_name)
        assert model_class is not None, model_name
        model_class.objects.filter(who__icontains="sarah").update(releaser=sarahboyce)
        model_class.objects.filter(who__icontains="natalia").update(releaser=nessita)


class Migration(migrations.Migration):

    dependencies = [
        (
            "generator",
            "0016_releaser_alpharelease_releaser_betarelease_releaser_and_more",
        ),
    ]

    operations = [
        migrations.RunPython(populate_releasers, migrations.RunPython.noop),
    ]
