from __future__ import absolute_import, unicode_literals
import os
from celery import Celery
from celery.schedules import crontab

# Set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ardurportal.settings')

app = Celery('ardurportal')

# Using a string here means the worker doesn't have to serialize
# the configuration object to child processes.
# - namespace='CELERY' means all celery-related config keys should have a `CELERY_` prefix.
app.config_from_object('django.conf:settings', namespace='CELERY')

# Load task modules from all registered Django app configs.
app.autodiscover_tasks()

@app.task(bind=True)
def debug_task(self):
    print('Request: {0!r}'.format(self.request))

# Celery Beat Schedule
app.conf.beat_schedule = {
    'mark-absent-users-every-midnight': {
        'task': 'aps.tasks.mark_absent_users',
        'schedule': crontab(hour=0, minute=0),  # Runs every midnight
    },
    'calculate-daily-attendance-every-midnight': {
        'task': 'aps.tasks.calculate_daily_attendance',
        'schedule': crontab(hour=0, minute=0),  # Runs every midnight
    },
}

# Timezone settings (ensure it's in your settings file as well)
app.conf.timezone = 'Asia/Kolkata'
