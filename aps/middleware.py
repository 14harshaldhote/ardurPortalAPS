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
