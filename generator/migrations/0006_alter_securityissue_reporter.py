# Generated by Django 5.2.dev20240628132121 on 2024-06-28 19:22

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("generator", "0005_featurerelease_alter_securityissue_description_and_more"),
    ]

    operations = [
        migrations.AlterField(
            model_name="securityissue",
            name="reporter",
            field=models.CharField(blank=True, max_length=1024),
        ),
    ]
