# Generated by Django 5.1.4 on 2025-01-06 11:42

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('aps', '0008_alter_userdetails_blood_group_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='userdetails',
            name='first_name',
        ),
        migrations.RemoveField(
            model_name='userdetails',
            name='last_name',
        ),
        migrations.AlterField(
            model_name='userdetails',
            name='aadharno',
            field=models.CharField(blank=True, max_length=12, null=True),
        ),
        migrations.AlterField(
            model_name='userdetails',
            name='contact_number_primary',
            field=models.CharField(blank=True, max_length=15, null=True),
        ),
        migrations.AlterField(
            model_name='userdetails',
            name='emergency_contact_address',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='userdetails',
            name='emergency_contact_name',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='userdetails',
            name='emergency_contact_primary',
            field=models.CharField(blank=True, max_length=15, null=True),
        ),
        migrations.AlterField(
            model_name='userdetails',
            name='employment_status',
            field=models.CharField(blank=True, choices=[('active', 'Active'), ('inactive', 'Inactive'), ('terminated', 'Terminated'), ('resigned', 'Resigned'), ('suspended', 'Suspended')], max_length=50),
        ),
        migrations.AlterField(
            model_name='userdetails',
            name='job_description',
            field=models.CharField(blank=True, max_length=100),
        ),
        migrations.AlterField(
            model_name='userdetails',
            name='panno',
            field=models.CharField(blank=True, help_text='Enter the PAN number of the user, if available.', max_length=20, null=True, validators=[django.core.validators.RegexValidator(message='Invalid PAN number format.', regex='^[A-Z]{5}[0-9]{4}[A-Z]{1}$')]),
        ),
        migrations.AlterField(
            model_name='userdetails',
            name='personal_email',
            field=models.EmailField(blank=True, max_length=254, null=True),
        ),
    ]
