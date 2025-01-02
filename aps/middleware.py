from django.utils import timezone
from django.contrib.auth.models import User
from .models import UserSession
import pytz

IST_TIMEZONE = pytz.timezone('Asia/Kolkata')

class IdleTimeTrackingMiddleware:
    """
    Middleware to track idle time and auto-logout after 5 minutes of inactivity.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # If the user is authenticated and active
        if request.user.is_authenticated:
            user_session = UserSession.objects.filter(
                user=request.user,
                session_key=request.session.session_key,
                logout_time__isnull=True
            ).last()

            if user_session:
                # Check if idle time has exceeded 5 minutes
                idle_threshold = timezone.timedelta(minutes=5)
                last_activity = user_session.last_activity or user_session.login_time
                if timezone.now() - last_activity > idle_threshold:
                    print(f"User {request.user.username} has been idle for more than 5 minutes. Logging out.")
                    # Auto logout after idle time
                    user_session.logout_time = timezone.now()
                    user_session.save()

        response = self.get_response(request)
        return response

from datetime import timedelta
from django.utils import timezone
from django.contrib.auth.models import User
from django.contrib.auth import logout
from django.utils.deprecation import MiddlewareMixin

class AutoLogoutMiddleware(MiddlewareMixin):
    def process_request(self, request):
        if request.user.is_authenticated:
            # Track session expiration (12 hours)
            session_age = timezone.now() - request.session.get('last_activity', timezone.now())
            max_session_duration = timedelta(seconds=43200)  # 12 hours

            if session_age > max_session_duration:
                logout(request)
                return None  # User logged out, so no need to process the request

            # Update the last activity timestamp
            request.session['last_activity'] = timezone.now()

            # Track inactivity (5 minutes)
            inactivity_time = request.session.get('inactivity_time', 0)
            max_inactivity_time = timedelta(minutes=5)

            if inactivity_time > max_inactivity_time.total_seconds():
                logout(request)
                return None  # User logged out due to inactivity

            # Update inactivity time
            request.session['inactivity_time'] = inactivity_time + 1

        return None
