# Generated by Django 5.1.4 on 2024-12-27 13:29

import django.db.models.deletion
import django.utils.timezone
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('aps', '0002_usersession_idle_time_usersession_last_activity'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='ITSupportTicket',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ticket_id', models.CharField(editable=False, max_length=10, unique=True)),
                ('issue_type', models.CharField(choices=[('Hardware Issue', 'Hardware Issue'), ('Software Issue', 'Software Issue'), ('Network Issue', 'Network Issue'), ('Internet Issue', 'Internet Issue'), ('Application Issue', 'Application Issue')], max_length=50)),
                ('description', models.TextField()),
                ('status', models.CharField(choices=[('Open', 'Open'), ('In Progress', 'In Progress'), ('Resolved', 'Resolved'), ('Closed', 'Closed')], default='Open', max_length=20)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='tickets', to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]