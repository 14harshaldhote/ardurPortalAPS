# Generated by Django 5.1.4 on 2025-01-19 10:52

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('aps', '0003_break'),
    ]

    operations = [
        migrations.AddField(
            model_name='break',
            name='reason_for_extension',
            field=models.TextField(blank=True, null=True),
        ),
    ]
