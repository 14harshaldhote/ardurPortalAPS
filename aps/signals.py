# signals.py (for tracking login and logout)

from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.dispatch import receiver
from django.utils import timezone
import pytz
from django.contrib.sessions.models import Session
from .models import UserSession

# Track login time
@receiver(user_logged_in)
def track_login_time(sender, request, user, **kwargs):
    request.session.save()
    session_key = request.session.session_key
    
    # Convert current time to IST before saving
    ist_tz = pytz.timezone('Asia/Kolkata')
    ist_now = timezone.now().astimezone(ist_tz)
    
    user_activity, created = UserSession.objects.get_or_create(
        user=user, 
        session_key=session_key,
        defaults={'login_time': ist_now}
    )
    if not created:
        user_activity.login_time = ist_now
        user_activity.save()

# Track logout time
@receiver(user_logged_out)
def track_logout_time(sender, request, user, **kwargs):
    request.session.save()
    session_key = request.session.session_key
    try:
        user_activity = UserSession.objects.filter(
            user=user, 
            session_key=session_key, 
            logout_time__isnull=True
        ).last()
        
        if user_activity:
            # Convert current time to IST before saving
            ist_tz = pytz.timezone('Asia/Kolkata')
            ist_now = timezone.now().astimezone(ist_tz)
            user_activity.logout_time = ist_now
            user_activity.save()
    except Exception as e:
        print(f"Error tracking logout time: {e}")

from django.db.models.signals import m2m_changed
from django.dispatch import receiver
from django.contrib.auth.models import User

@receiver(m2m_changed, sender=User.groups.through)
def log_group_change(sender, instance, action, **kwargs):
    if action == 'post_add':
        print(f"User {instance.username} added to group(s): {', '.join([group.name for group in instance.groups.all()])}")
    elif action == 'post_remove':
        print(f"User {instance.username} removed from group(s): {', '.join([group.name for group in instance.groups.all()])}")
