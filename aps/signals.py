from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.dispatch import receiver
from django.utils import timezone
from .models import UserSession, Attendance

@receiver(user_logged_in)
def track_login_time(sender, request, user, **kwargs):
    try:
        session_key = request.session.session_key
        if not session_key:
            request.session.save()
            session_key = request.session.session_key

        local_now = timezone.now()
        print(f"Login time for {user.username}: {local_now}")

        # Create UserSession
        UserSession.objects.create(
            user=user,
            session_key=session_key,
            login_time=local_now
        )
        print(f"Created new session for user: {user.username}, session key: {session_key}, login time: {local_now}")

        # Handle attendance
        today = local_now.date()
        attendance, created = Attendance.objects.get_or_create(
            user=user,
            date=today,
            defaults={
                'status': 'Present',
                'clock_in_time': local_now
            }
        )

        if created:
            print(f"Created new attendance record for user: {user.username}")
            print(f"Date: {today}")
            print(f"Clock-in time: {local_now}")
            print(f"Status: {attendance.status}")
        elif not attendance.clock_in_time:
            attendance.status = 'Present'
            attendance.clock_in_time = local_now
            attendance.save()
            print(f"Updated existing attendance record for user: {user.username}")
            print(f"Date: {today}")
            print(f"Updated clock-in time: {local_now}")
            print(f"Updated status: {attendance.status}")
        else:
            print(f"Existing attendance record found for user: {user.username}")
            print(f"Date: {today}")
            print(f"Existing clock-in time: {attendance.clock_in_time}")
            print(f"Current status: {attendance.status}")

    except Exception as e:
        print(f"Error in track_login_time: {str(e)}")

@receiver(user_logged_out)
def track_logout_time(sender, request, user, **kwargs):
    try:
        session_key = request.session.session_key
        local_now = timezone.now()
        print(f"Logout time for {user.username}: {local_now}")

        # Update UserSession
        if session_key:
            user_session = UserSession.objects.filter(
                user=user,
                session_key=session_key,
                logout_time__isnull=True
            ).first()

            if user_session:
                user_session.logout_time = local_now
                user_session.save()
                print(f"Updated session for user: {user.username}")
                print(f"Session key: {session_key}")
                print(f"Login time: {user_session.login_time}")
                print(f"Logout time: {local_now}")

        # Update Attendance
        today = local_now.date()
        attendance = Attendance.objects.filter(
            user=user,
            date=today,
            status='Present'  # Only update if already marked Present
        ).first()

        if attendance and attendance.clock_in_time:
            previous_time = attendance.total_hours if attendance.total_hours else "No previous hours"
            attendance.clock_out_time = local_now
            attendance.total_hours = timezone.timedelta(
                seconds=(local_now - attendance.clock_in_time).total_seconds()
            )
            attendance.save()
            print(f"Updated attendance record for user: {user.username}")
            print(f"Date: {today}")
            print(f"Clock-in time: {attendance.clock_in_time}")
            print(f"Clock-out time: {local_now}")
            print(f"Previous total hours: {previous_time}")
            print(f"New total hours: {attendance.total_hours}")
            print(f"Status: {attendance.status}")

    except Exception as e:
        print(f"Error in track_logout_time: {str(e)}")