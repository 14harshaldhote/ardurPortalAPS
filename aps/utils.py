from django.utils.timezone import now
from aps.models import Attendance, User  # Adjust to your app name

def mark_absent_for_non_logged_in_users():
    today = now().date()
    
    # Get all users
    all_users = User.objects.all()
    
    # Get users who already have attendance for today
    attended_users = Attendance.objects.filter(date=today).values_list('user_id', flat=True)
    
    # Find users without attendance for today
    absent_users = all_users.exclude(id__in=attended_users)
    
    # Prepare attendance records for absent users
    attendance_records = [
        Attendance(user=user, date=today, status='Absent') for user in absent_users
    ]
    
    # Bulk create attendance records for absent users
    Attendance.objects.bulk_create(attendance_records)
