# Generated by Django 5.1.4 on 2025-01-02 06:40

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('aps', '0017_rename_emp_id_leavebalance_user_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='attendance',
            name='clock_in_time',
            field=models.TimeField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='attendance',
            name='clock_out_time',
            field=models.TimeField(blank=True, null=True),
        ),
    ]
