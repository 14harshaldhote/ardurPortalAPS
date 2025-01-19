from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.dispatch import receiver
from django.utils import timezone
from datetime import datetime, time
from .models import UserSession, Attendance

from datetime import timedelta

# Signal handlers
@receiver(user_logged_in)
def track_login_time(sender, request, user, **kwargs):
    try:
        session_key = request.session.session_key
        if not session_key:
            request.session.save()
            session_key = request.session.session_key
        
        local_now = timezone.now()
        
        # Create UserSession for login
        user_session = UserSession.objects.create(
            user=user,
            session_key=session_key,
            login_time=local_now,
            location=request.session.get('location', 'Office')  # Default to Office if not specified
        )

        # Get or create attendance record
        today = local_now.date()
        attendance, created = Attendance.objects.get_or_create(
            user=user,
            date=today
        )
        
        # Calculate attendance will handle the status
        attendance.save()
        
        print(f"Login tracked for {user.username} on {today}")
    except Exception as e:
        print(f"Error in track_login_time: {str(e)}")

@receiver(user_logged_out)
def track_logout_time(sender, request, user, **kwargs):
    try:
        session_key = request.session.session_key
        local_now = timezone.now()
        
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
        
        # Update Attendance
        today = local_now.date()
        attendance = Attendance.objects.filter(
            user=user,
            date=today
        ).first()
        
        if attendance:
            attendance.save()  # This will trigger calculate_attendance()
            
        print(f"Logout tracked for {user.username} on {today}")
    except Exception as e:
        print(f"Error in track_logout_time: {str(e)}")