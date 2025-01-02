from aps.models import Attendance
from django.contrib.auth.models import User
from celery import shared_task
from django.utils import timezone

# Celery task to mark users as absent who didn't log in today
@shared_task
def mark_absent_users():
    # Get today's date
    today = timezone.now().date()

    # Get all users
    users = User.objects.all()

    for user in users:
        # Check if the user has logged in today
        if not user.last_login or user.last_login.date() != today:
            # Create or update attendance status for users who haven't logged in
            attendance, created = Attendance.objects.get_or_create(
                user=user,
                date=today,
                defaults={
                    'status': 'Absent',
                }
            )
            if not created and attendance.status != 'Absent':
                attendance.status = 'Absent'
                attendance.save()
                print(f"Marked {user.username} as 'Absent' for {today}")
        else:
            print(f"{user.username} has logged in today.")

# Celery task to calculate attendance for the day
@shared_task
def calculate_daily_attendance():
    date_today = timezone.now().date()

    # Fetch all users
    users = User.objects.all()

    for user in users:
        # Fetch or create attendance for today
        attendance, created = Attendance.objects.get_or_create(
            user=user,
            date=date_today
        )

        # If attendance doesn't exist or status is 'Pending', calculate it
        if created or attendance.status == 'Pending':
            print(f"Calculating attendance for user: {user.username}, date: {date_today}")
            attendance.calculate_attendance()
            attendance.save()
            print(f"Attendance for {user.username} on {date_today} has been calculated.")
