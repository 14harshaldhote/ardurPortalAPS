from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.dispatch import receiver
from django.utils import timezone
from datetime import datetime, time
from .models import UserSession, Attendance

from datetime import timedelta

# signals.py
@receiver(user_logged_in)
def track_login_time(sender, request, user, **kwargs):
    """Handle user login and create/update attendance records"""
    try:
        if not request.session.session_key:
            request.session.save()

        local_now = timezone.now()
        
        # Create session record
        session = UserSession.objects.create(
            user=user,
            session_key=request.session.session_key,
            login_time=local_now,
            ip_address=request.META.get('REMOTE_ADDR'),
            location=request.session.get('location', 'Office')
        )

        # Update attendance
        attendance, _ = Attendance.objects.get_or_create(
            user=user,
            date=local_now.date(),
        )
        
        # Force recalculation of attendance using new parameter name
        attendance.save(recalculate=True)

        print(f"Login tracked successfully - User: {user.username}, "
              f"Time: {local_now}, Session: {session.session_key}")

    except Exception as e:
        print(f"Critical error in track_login_time: {str(e)}")
        raise

@receiver(user_logged_out)
def track_logout_time(sender, request, user, **kwargs):
    """Handle user logout and update attendance records"""
    try:
        local_now = timezone.now()
        
        if request.session.session_key:
            session = UserSession.objects.filter(
                user=user,
                session_key=request.session.session_key,
                logout_time__isnull=True
            ).first()

            if session:
                session.end_session()

        attendance = Attendance.objects.filter(
            user=user,
            date=local_now.date()
        ).first()

        if attendance:
            attendance.save(recalculate=True)  # Using new parameter name

        print(f"Logout tracked successfully - User: {user.username}, Time: {local_now}")

    except Exception as e:
        print(f"Critical error in track_logout_time: {str(e)}")
        raise