from django.utils import timezone
from django.contrib.auth.models import User, Group
import pytz
from django.db import models
from django.utils.timezone import now



IST_TIMEZONE = pytz.timezone('Asia/Kolkata')

class UserSession(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    session_key = models.CharField(max_length=40, unique=True)
    login_time = models.DateTimeField(default=timezone.now)
    logout_time = models.DateTimeField(null=True, blank=True)
    working_hours = models.DurationField(null=True, blank=True)
    idle_time = models.DurationField(null=True, blank=True)
    last_activity = models.DateTimeField(null=True, blank=True)


    def get_login_time_in_ist(self):
        if self.login_time:
            return timezone.localtime(self.login_time)
        return None

    def get_logout_time_in_ist(self):
        if self.logout_time:
            return timezone.localtime(self.logout_time)
        return None

    def save(self, *args, **kwargs):
        print(f"Saving UserSession for user: {self.user.username}, session_key: {self.session_key}")
        
        # Ensure login_time and logout_time are timezone-aware
        if self.login_time and not timezone.is_aware(self.login_time):
            self.login_time = timezone.make_aware(self.login_time, IST_TIMEZONE)
        
        if self.logout_time and not timezone.is_aware(self.logout_time):
            self.logout_time = timezone.make_aware(self.logout_time, IST_TIMEZONE)
        
        if self.logout_time:
            self.calculate_working_hours()

        if self.last_activity and self.logout_time:
            self.calculate_idle_time()

        super().save(*args, **kwargs)

    def calculate_working_hours(self):
        print(f"Calculating working hours for session: {self.session_key}")
        """Calculate working hours based on login_time and logout_time."""
        if self.logout_time:
            self.working_hours = self.logout_time - self.login_time

    def calculate_idle_time(self):
        print(f"Calculating idle time for session: {self.session_key}")
        """Calculate idle time based on last_activity and logout_time."""
        if self.last_activity and self.logout_time:
            active_threshold = timezone.timedelta(minutes=5)
            time_since_last_activity = self.logout_time - self.last_activity
            if time_since_last_activity > active_threshold:
                self.idle_time = time_since_last_activity - active_threshold
            else:
                self.idle_time = timezone.timedelta(0)

    def update_activity(self):
        print(f"Updating last activity for session: {self.session_key}")
        """Update last_activity to the current time."""
        self.last_activity = timezone.now()
        self.save(update_fields=['last_activity'])

    def is_online(self):
        """Returns True if the user is online, else False"""
        return self.logout_time is None

'''---------- ATTENDANCE AREA ----------'''

from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone

class Leave(models.Model):
    LEAVE_TYPES = [
        ('Sick Leave', 'Sick Leave'),
        ('Casual Leave', 'Casual Leave'),
        ('Earned Leave', 'Earned Leave'),
        ('Loss of Pay', 'Loss of Pay'),
    ]
    
    STATUS_CHOICES = [
        ('Pending', 'Pending'),
        ('Approved', 'Approved'),
        ('Rejected', 'Rejected'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    leave_type = models.CharField(max_length=50, choices=LEAVE_TYPES)
    start_date = models.DateField()
    end_date = models.DateField()
    leave_days = models.IntegerField(null=True, blank=True)
    reason = models.TextField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Pending')
    approver = models.ForeignKey(
        User, related_name='leave_approvals', on_delete=models.SET_NULL, null=True, blank=True
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Leave Request by {self.user.username} for {self.leave_type}"

    def calculate_leave_days(self):
        if self.start_date and self.end_date:
            self.leave_days = (self.end_date - self.start_date).days + 1
            return self.leave_days

    def save(self, *args, **kwargs):
        if not self.leave_days:
            self.leave_days = self.calculate_leave_days()
        super().save(*args, **kwargs)
        self.update_attendance_status()

    def update_attendance_status(self):
        """Update attendance status for the user during the leave period"""
        if self.status == 'Approved':
            attendance_records = Attendance.objects.filter(
                user=self.user,
                date__range=[self.start_date, self.end_date]
            )
            for attendance in attendance_records:
                attendance.status = 'On Leave'
                attendance.save()

    @classmethod
    def get_leave_balance(cls, user):
        """Calculate leave balance dynamically"""
        TOTAL_LEAVES = 18  # Annual leave allocation, adjust as necessary

        # Get approved leaves
        approved_leaves = cls.objects.filter(
            user=user,
            status='Approved',
            start_date__year=timezone.now().year
        ).aggregate(
            total_days=models.Sum('leave_days')
        )['total_days'] or 0

        # Get pending leaves
        pending_leaves = cls.objects.filter(
            user=user,
            status='Pending',
            start_date__year=timezone.now().year
        ).aggregate(
            total_days=models.Sum('leave_days')
        )['total_days'] or 0

        available_leave = TOTAL_LEAVES - approved_leaves - pending_leaves

        return {
            'total_leave': TOTAL_LEAVES,
            'consumed_leave': approved_leaves,
            'pending_leave': pending_leaves,
            'available_leave': available_leave,
        }


    
    @classmethod
    def can_apply_leave(cls, user, requested_days):
        """Check if user can apply for leave"""
        balance = cls.get_leave_balance(user)
        return balance['available_leave'] >= requested_days


class Attendance(models.Model):
    STATUS_CHOICES = [
        ('Present', 'Present'),
        ('Absent', 'Absent'), 
        ('Pending', 'Pending'),
        ('On Leave', 'On Leave'),
        ('Work From Home', 'Work From Home'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    date = models.DateField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Pending')
    clock_in_time = models.TimeField(null=True, blank=True)
    clock_out_time = models.TimeField(null=True, blank=True)
    total_hours = models.DurationField(null=True, blank=True)
    leave_request = models.ForeignKey(
        'Leave', on_delete=models.SET_NULL, null=True, blank=True, 
        related_name='attendances'
    )

    def calculate_attendance(self):
        print(f"Calculating attendance for user: {self.user.username}, date: {self.date}")

        try:
            # If the status is 'On Leave', don't calculate clock-in/out
            if self.status == 'On Leave':
                self.clock_in_time = None
                self.clock_out_time = None
                self.total_hours = None
                return

            # If we already have clock-in time and it's not from a session calculation
            if self.clock_in_time and self.status == 'Present':
                print(f"Using existing clock-in time for {self.user.username}")
                return

            # Get UserSessions for the user on the given date
            user_sessions = UserSession.objects.filter(
                user=self.user,
                login_time__date=self.date
            ).order_by('login_time')

            print(f"Found {user_sessions.count()} session(s) for user {self.user.username} on {self.date}")

            if user_sessions.exists():
                first_session = user_sessions.first()
                last_session = user_sessions.last()

                # Only update if we don't already have clock-in time
                if not self.clock_in_time and first_session.login_time:
                    self.clock_in_time = first_session.login_time
                    self.status = 'Present'

                # Update clock-out and total hours if we have a logout time
                if last_session.logout_time:
                    self.clock_out_time = last_session.logout_time
                    if self.clock_in_time:
                        self.total_hours = last_session.logout_time - self.clock_in_time

            # Don't override status if it's already Present
            elif self.status != 'Present':
                self.status = 'Pending'
                if not self.clock_in_time:  # Only clear if not manually set
                    self.clock_in_time = None
                    self.clock_out_time = None
                    self.total_hours = None

        except Exception as e:
            print(f"Error calculating attendance: {e}")
            if self.status != 'Present':  # Don't override if already Present
                self.status = 'Pending'

    def save(self, *args, **kwargs):
        print(f"Saving attendance for user: {self.user.username}, date: {self.date}")
        self.calculate_attendance()
        super().save(*args, **kwargs)
        print(f"Attendance saved for user: {self.user.username}, date: {self.date}, "
              f"status: {self.status}, clock-in: {self.clock_in_time}, "
              f"clock-out: {self.clock_out_time}, total hours: {self.total_hours}")

'''-------------------------------------------- IT SUPPORT AREA ---------------------------------------'''


# IT Support Ticket model to track and manage IT support requests
class ITSupportTicket(models.Model):
    STATUS_CHOICES = [
        ('Open', 'Open'),
        ('In Progress', 'In Progress'),
        ('Resolved', 'Resolved'),
        ('Closed', 'Closed'),
    ]

    ISSUE_TYPE_CHOICES = [
        ('Hardware Issue', 'Hardware Issue'),
        ('Software Issue', 'Software Issue'),
        ('Network Issue', 'Network Issue'),
        ('Internet Issue', 'Internet Issue'),
        ('Application Issue', 'Application Issue'),
    ]

    ticket_id = models.CharField(max_length=10, unique=True, editable=False)  # Unique ticket identifier
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='tickets')  # User who raised the ticket
    issue_type = models.CharField(max_length=50, choices=ISSUE_TYPE_CHOICES)  # Type of issue reported
    subject = models.CharField(max_length=100, default="No subject")  # Add default value
    description = models.TextField()  # Detailed description of the issue
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Open')  # Ticket status
    created_at = models.DateTimeField(default=now)  # Time when ticket was created
    updated_at = models.DateTimeField(auto_now=True)  # Time when ticket was last updated

    def save(self, *args, **kwargs):
        """Override save method to generate ticket ID if not provided."""
        if not self.ticket_id:
            self.ticket_id = self.generate_ticket_id()
        super().save(*args, **kwargs)

    def generate_ticket_id(self):
        """Generate a unique ticket ID based on the date."""
        today = now().strftime('%Y%m%d')
        count = ITSupportTicket.objects.filter(created_at__date=now().date()).count() + 1
        return f"TK{today}{count:03}"

    def __str__(self):
        """Return a string representation of the ticket."""
        return f"{self.ticket_id} - {self.issue_type} - {self.status}"


# Employee model to store employee-specific information
class Employee(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)  # Reference to the User model
    shift = models.CharField(max_length=10, choices=[('Day', 'Day'), ('Night', 'Night')])  # Shift the employee works
    leave_balance = models.IntegerField(default=18)  # Number of leaves the employee has
    attendance_record = models.PositiveIntegerField(default=0)  # Number of days the employee worked
    late_arrivals = models.PositiveIntegerField(default=0)  # Number of times the employee was late
    early_departures = models.PositiveIntegerField(default=0)  # Number of times the employee left early

    def __str__(self):
        """Return a string representation of the employee."""
        return f"{self.user.username} - {', '.join([group.name for group in self.user.groups.all()])}"
    
''' ------------------------------------------- PROFILE AREA ------------------------------------------- '''
from django.core.exceptions import ValidationError

from django.db import models
from django.core.validators import RegexValidator
from django.contrib.auth.models import User, Group

class UserDetails(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    
    dob = models.DateField(null=True, blank=True)
    blood_group = models.CharField(
        max_length=10, 
        choices=[ ('', '--------'),
            ('A+', 'A+'),
            ('A-', 'A-'),
            ('B+', 'B+'),
            ('B-', 'B-'),
            ('AB+', 'AB+'),
            ('AB-', 'AB-'),
            ('O+', 'O+'),
            ('O-', 'O-'),
        ], 
        null=True, 
        blank=True, 
        default='Unknown'
    )
    hire_date = models.DateField(null=True, blank=True)
    gender = models.CharField(max_length=10, choices=[('', '--------'),('Male', 'Male'), ('Female', 'Female'), ('Other', 'Other')], null=True, blank=True)
    
    panno = models.CharField(max_length=10, null=True, blank=True)

    job_description = models.TextField(null=True, blank=True)
    employment_status = models.CharField(
        max_length=50,
        choices=[ 
            ('', '--------'),
            ('active', 'Active'),
            ('inactive', 'Inactive'),
            ('terminated', 'Terminated'),
            ('resigned', 'Resigned'),
            ('suspended', 'Suspended'),
        ],
        blank=True,         null=True, 
 # No default value here
    )
    emergency_contact_address = models.TextField(null=True, blank=True)
    emergency_contact_primary = models.CharField(max_length=10, null=True, blank=True)
    emergency_contact_name = models.CharField(max_length=100, null=True, blank=True)
    start_date = models.DateField(null=True, blank=True)
    work_location = models.CharField(max_length=100, null=True, blank=True)
    contact_number_primary = models.CharField(max_length=10, null=True, blank=True)
    personal_email = models.EmailField(null=True, blank=True)
    aadharno = models.CharField(max_length=14, null=True, blank=True)  # To store Aadhar with spaces
    group = models.ForeignKey('auth.Group', on_delete=models.SET_NULL, null=True, blank=True)

    # Ensure the contact number is in the correct format

    def __str__(self):
        return f"Details for {self.user.username}" 



''' ------------------------------------------- PROJECT AREA ------------------------------------------- '''

# Project model with embedded assignment information


class Project(models.Model):
    name = models.CharField(max_length=100)  # Project name
    description = models.TextField()  # Description of the project
    deadline = models.DateField()  # Deadline for the project
    status = models.CharField(
        max_length=20, 
        choices=[('Completed', 'Completed'), ('In Progress', 'In Progress'), ('Pending', 'Pending')]
    )  # Status of the project
    created_at = models.DateTimeField(auto_now_add=True)  # Time when the project was created
    users = models.ManyToManyField(User, through='ProjectAssignment', related_name='projects')  # Users assigned to the project

    def __str__(self):
        """Return the project name."""
        return self.name

    def is_overdue(self):
        """Check if the project is overdue based on the deadline."""
        return self.deadline < timezone.now().date() and self.status != 'Completed'

    @classmethod
    def is_valid_status(cls, status):
        """Check if the status is valid."""
        return status in dict(cls._meta.get_field('status').choices)


class ProjectAssignment(models.Model):
    project = models.ForeignKey(Project, on_delete=models.CASCADE)  # The project being assigned
    user = models.ForeignKey(User, on_delete=models.CASCADE)  # The user being assigned to the project
    assigned_date = models.DateField(auto_now_add=True)  # Date of assignment
    hours_worked = models.FloatField(default=0.0)  # Total hours worked by the user on the project
    role_in_project = models.CharField(
        max_length=50, 
        choices=[('Manager', 'Manager'), ('Developer', 'Developer'), ('Support', 'Support'), 
                 ('Apprisal', 'Apprisal'), ('Tester', 'Tester')]
    )  # Role of the user in the project

    def __str__(self):
        """Return a string representation of the project assignment."""
        return f"{self.user.username} assigned to {self.project.name}"

    def get_total_hours(self):
        """Calculate total hours worked by a user on a project."""
        return self.hours_worked

''' ------------------------------------------- TRACK AREA ------------------------------------------- '''


# FailedLoginAttempt model to track failed login attempts
class FailedLoginAttempt(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)  # User who attempted to log in
    attempt_time = models.DateTimeField(auto_now_add=True)  # Time of the failed login attempt
    ip_address = models.GenericIPAddressField()  # IP address from which the failed login attempt was made

    def __str__(self):
        """Return a string representation of the failed login attempt."""
        return f"Failed login for {self.user.username} from {self.ip_address}"


# PasswordChange model to store password change logs
class PasswordChange(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)  # User who changed the password
    old_password = models.CharField(max_length=255)  # Old password before the change
    new_password = models.CharField(max_length=255)  # New password after the change
    change_time = models.DateTimeField(auto_now_add=True)  # Time when the password was changed

    def __str__(self):
        """Return a string representation of the password change."""
        return f"Password change for {self.user.username} at {self.change_time}"


# RoleAssignmentAudit model to track role assignment history
class RoleAssignmentAudit(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)  # User whose role was changed
    role_assigned = models.CharField(max_length=50)  # Role that was assigned
    assigned_by = models.ForeignKey(User, related_name="role_assigned_by", on_delete=models.CASCADE)  # Admin user who assigned the role
    assigned_date = models.DateTimeField(auto_now_add=True)  # Date when the role was assigned

    def __str__(self):
        """Return a string representation of the role assignment."""
        return f"{self.user.username} assigned {self.role_assigned} by {self.assigned_by.username}"


# SystemUsage model to store system usage data
class SystemUsage(models.Model):
    peak_time_start = models.DateTimeField()  # Start time of peak system usage
    peak_time_end = models.DateTimeField()  # End time of peak system usage
    active_users_count = models.PositiveIntegerField()  # Number of active users during peak time

    def __str__(self):
        """Return a string representation of the system usage period."""
        return f"Peak usage: {self.peak_time_start} - {self.peak_time_end}"


# FeatureUsage model to track usage of specific system features
class FeatureUsage(models.Model):
    feature_name = models.CharField(max_length=100)  # Name of the feature
    usage_count = models.PositiveIntegerField()  # Number of times the feature was used

    def __str__(self):
        """Return a string representation of the feature usage."""
        return f"{self.feature_name} - {self.usage_count} uses"


# SystemError model to store information about system errors
class SystemError(models.Model):
    error_message = models.TextField()  # Description of the system error
    error_time = models.DateTimeField(auto_now_add=True)  # Time when the error occurred
    resolved = models.BooleanField(default=False)  # Whether the error is resolved

    def __str__(self):
        """Return a string representation of the system error."""
        return f"Error: {self.error_message[:50]} - Resolved: {self.resolved}"


# UserComplaint model to track user complaints
class UserComplaint(models.Model):
    employee = models.ForeignKey(Employee, on_delete=models.CASCADE)  # Employee who raised the complaint
    complaint = models.TextField()  # Complaint details
    complaint_date = models.DateTimeField(auto_now_add=True)  # Date when the complaint was made
    status = models.CharField(max_length=20, choices=[('Resolved', 'Resolved'), ('Pending', 'Pending')])  # Status of the complaint

    def __str__(self):
        """Return a string representation of the user complaint."""
        return f"Complaint by {self.employee.user.username} - Status: {self.status}"


''' ------------------------------------------------- TIMESHEET AREA --------------------------------------------------- '''


class Timesheet(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='timesheets')
    week_start_date = models.DateField()
    project_name = models.CharField(max_length=255)
    task_name = models.CharField(max_length=255)
    hours = models.FloatField()
    approval_status = models.CharField(
        max_length=10,
        choices=[('Pending', 'Pending'), ('Approved', 'Approved'), ('Rejected', 'Rejected')],
        default='Pending'
    )
    manager_comments = models.TextField(blank=True, null=True)  # Allows manager to provide feedback
    submitted_at = models.DateTimeField(auto_now_add=True)  # Tracks when the timesheet was submitted
    reviewed_at = models.DateTimeField(null=True, blank=True)  # Tracks when the timesheet was reviewed

    def __str__(self):
        return f"Timesheet for {self.project_name} - {self.week_start_date}"

    class Meta:
        unique_together = ('user', 'week_start_date', 'project_name', 'task_name')
        ordering = ['-week_start_date']


'''------------------------------------------------ CHAT AREA ---------------------------------------'''


class Chat(models.Model):
    participants = models.ManyToManyField(User)
    created_at = models.DateTimeField(auto_now_add=True)


class Message(models.Model):
    chat = models.ForeignKey(Chat, on_delete=models.CASCADE, related_name="messages")
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name="sent_messages")
    recipient = models.ForeignKey(User, on_delete=models.CASCADE, related_name="received_messages")
    content = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
