from django.utils import timezone
from django.contrib.auth.models import User, Group
import pytz
from django.db import models
from django.utils.timezone import now
from django.conf import settings
from datetime import timedelta
from django.dispatch import receiver




IST_TIMEZONE = pytz.timezone('Asia/Kolkata')

'''------------------------- CLINET PROFILE --------------------'''
class ClientProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='client_profile')
    company_name = models.CharField(max_length=100)
    contact_info = models.TextField()
    
    # Professional Level Details
    industry_type = models.CharField(max_length=100)  # Industry type the company belongs to
    company_size = models.CharField(
        max_length=50, 
        choices=[('Small', 'Small'), ('Medium', 'Medium'), ('Large', 'Large')],  # Company size categories
        default='Small'
    )
    registration_number = models.CharField(max_length=50, blank=True, null=True)  # Business registration number
    business_location = models.CharField(max_length=255, blank=True, null=True)  # Location of the business
    website_url = models.URLField(blank=True, null=True)  # Company website URL
    year_established = models.IntegerField(blank=True, null=True)  # Year the company was established
    annual_revenue = models.DecimalField(
        max_digits=15, decimal_places=2, blank=True, null=True
    )  # Annual revenue of the company (optional field)

    def __str__(self):
        return self.company_name
'''------------------------- USERSESSION --------------------'''
class UserSession(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    session_key = models.CharField(max_length=40, unique=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    login_time = models.DateTimeField(default=timezone.now)
    logout_time = models.DateTimeField(null=True, blank=True)
    working_hours = models.DurationField(null=True, blank=True)
    idle_time = models.DurationField(default=timedelta(0))
    last_activity = models.DateTimeField(default=timezone.now)
    location = models.CharField(max_length=50, null=True, blank=True)

    def save(self, *args, **kwargs):
        
        current_time = timezone.now()

        # If this is a new session, set last_activity to login_time
        if not self.pk:
            self.last_activity = self.login_time

        # If session is logged out, calculate working hours and idle time
        if self.logout_time:
            total_duration = self.logout_time - self.login_time
            time_since_last_activity = self.logout_time - self.last_activity

            # Calculate idle time if more than 1 minute has passed
            if time_since_last_activity > timedelta(minutes=1):
                self.idle_time = time_since_last_activity
            
            # Working hours: total session time minus idle time
            self.working_hours = total_duration - self.idle_time
        else:
            # For ongoing sessions, calculate working hours
            time_since_login = current_time - self.login_time
            time_since_last_activity = current_time - self.last_activity

            # If there was idle time (more than 1 minute), add it to idle_time
            if time_since_last_activity > timedelta(minutes=1):
                self.idle_time += time_since_last_activity

            # Working hours is current time minus login time minus idle time
            self.working_hours = time_since_login - self.idle_time

        # Set the location (based on IP address)
        self.location = self.determine_location()

        # Call the superclass save method
        super().save(*args, **kwargs)

    def determine_location(self):
        """Determine if the user is working from home or office based on IP address."""
        office_ips = ['203.0.113.0', '203.0.113.1', '203.0.113.2']  # Example office IPs
        return 'Office' if self.ip_address in office_ips else 'Home'

    def update_activity(self):
        """Update the last activity timestamp and recalculate times."""
        current_time = timezone.now()
        time_since_last_activity = current_time - self.last_activity
        
        # If more than 1 minute has passed, add to idle time
        if time_since_last_activity > timedelta(minutes=1):
            self.idle_time += time_since_last_activity
            
        self.last_activity = current_time
        self.working_hours = current_time - self.login_time - self.idle_time
        self.save()

    def end_session(self):
        """Properly end the session with correct time calculations."""
        current_time = timezone.now()
        
        # Calculate final idle time if needed
        time_since_last_activity = current_time - self.last_activity
        if time_since_last_activity > timedelta(minutes=1):
            self.idle_time += time_since_last_activity
            
        self.logout_time = current_time
        self.last_activity = current_time
        
        # Final working hours calculation
        total_session_time = self.logout_time - self.login_time
        self.working_hours = total_session_time - self.idle_time
        
        self.save()
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
    def calculate_lop_per_month(cls, user, month, year):
        """Calculate the number of Loss of Pay days taken per month for the user"""
        lop_leaves = cls.objects.filter(
            user=user,
            leave_type='Loss of Pay',
            status='Approved',
            start_date__year=year,
            start_date__month=month
        )
        
        # Count total LOP days in the given month
        total_lop_days = 0
        for leave in lop_leaves:
            # Add leave days for each leave request
            total_lop_days += leave.leave_days

        return total_lop_days


    
    @classmethod
    def can_apply_leave(cls, user, requested_days):
        """Check if user can apply for leave"""
        balance = cls.get_leave_balance(user)
        return balance['available_leave'] >= requested_days


from datetime import timedelta
from django.utils import timezone

class Attendance(models.Model):
    STATUS_CHOICES = [
        ('Present', 'Present'),
        ('Absent', 'Absent'),
        ('Pending', 'Pending'),
        ('On Leave', 'On Leave'),
        ('Work From Home', 'Work From Home'),
        ('Weekend', 'Weekend'),  # Added new status for weekends
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    date = models.DateField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Pending')
    clock_in_time = models.TimeField(null=True, blank=True)
    clock_out_time = models.TimeField(null=True, blank=True)
    total_hours = models.DurationField(null=True, blank=True)
    leave_request = models.ForeignKey(
        'LeaveRequest', on_delete=models.SET_NULL, null=True, blank=True, 
        related_name='attendances'
    )

    def calculate_total_hours(self):
        """Calculate the total hours worked based on clock-in and clock-out times."""
        if self.clock_in_time and self.clock_out_time:
            self.total_hours = self.clock_out_time - self.clock_in_time
            self.save()


    def calculate_attendance(self):
        print(f"Calculating attendance for user: {self.user.username}, date: {self.date}")

        try:
            # Check if it's weekend (Saturday or Sunday)
            if self.date.weekday() >= 5:  # 5 is Saturday, 6 is Sunday
                self.status = 'Weekend'
                self.clock_in_time = None
                self.clock_out_time = None
                self.total_hours = None
                return

            # Check for leave request first
            if self.leave_request:
                self.status = 'On Leave'
                self.clock_in_time = None
                self.clock_out_time = None
                self.total_hours = timedelta(seconds=0)
                return

            # Get all UserSessions for the user on the given date
            user_sessions = UserSession.objects.filter(
                user=self.user,
                login_time__date=self.date
            ).order_by('login_time')

            print(f"Found {user_sessions.count()} session(s) for user {self.user.username} on {self.date}")

            if user_sessions.exists():
                total_worked_seconds = 0
                first_session = user_sessions.first()
                last_session = user_sessions.last()

                # Calculate total working hours only for completed sessions
                for session in user_sessions:
                    if session.logout_time:
                        total_worked_seconds += (session.logout_time - session.login_time).total_seconds()

                # Set clock_in_time from first session
                self.clock_in_time = first_session.login_time.time()
                
                # Set clock_out_time from last session if it has logged out
                if last_session.logout_time:
                    self.clock_out_time = last_session.logout_time.time()
                
                self.total_hours = timedelta(seconds=total_worked_seconds)

                # Determine status based on session location
                if any(session.location == 'Home' for session in user_sessions):
                    self.status = 'Work From Home'
                else:
                    self.status = 'Present'
            else:
                # Only mark as absent if it's a working day and no leave request
                if not self.leave_request and self.date < timezone.now().date():
                    self.status = 'Absent'
                else:
                    self.status = 'Pending'
                self.clock_in_time = None
                self.clock_out_time = None
                self.total_hours = None

        except Exception as e:
            print(f"Error calculating attendance: {e}")
            self.status = 'Pending'

    def save(self, *args, **kwargs):
        print(f"Saving attendance for user: {self.user.username}, date: {self.date}")
        self.calculate_attendance()
        super().save(*args, **kwargs)
        print(f"Attendance saved for user: {self.user.username}, date: {self.date}, "
              f"status: {self.status}, clock-in: {self.clock_in_time}, "
              f"clock-out: {self.clock_out_time}, total hours: {self.total_hours}")

'''-------------------------------------------- SUPPORT AREA ---------------------------------------'''
import uuid
from django.db import models
from django.utils.timezone import now

def generate_ticket_id():
    """Generate a unique ticket ID based on UUID."""
    return uuid.uuid4()  # This will generate a full UUID

class Support(models.Model):
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
        ('HR Related Issue', 'HR Related Issue'),
    ]

    ASSIGNED_TO_CHOICES = [
        ('HR', 'HR'),
        ('Admin', 'Admin'),
    ]


    ticket_id = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)  # UUID ticket ID
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='tickets')  # User who raised the ticket
    issue_type = models.CharField(max_length=50, choices=ISSUE_TYPE_CHOICES)
    subject = models.CharField(max_length=100, default="No subject")
    description = models.TextField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Open')
    assigned_to = models.CharField(max_length=50, choices=ASSIGNED_TO_CHOICES, default='Admin')
    created_at = models.DateTimeField(default=now)
    updated_at = models.DateTimeField(auto_now=True)

    def save(self, *args, **kwargs):
        """Override save method to generate ticket ID if not provided."""
        if not self.ticket_id:
            self.ticket_id = self.generate_ticket_id()
        super().save(*args, **kwargs)

    def generate_ticket_id(self):
        """Generate a unique ticket ID based on UUID."""
        return uuid.uuid4()

    def __str__(self):
        """Return a string representation of the ticket."""
        return f"{self.ticket_id} - {self.issue_type} - {self.status} - {self.assigned_to}"

# IT Support Ticket model to track and manage IT support requests
''' ------------------------------------------- REmove employee AREA ------------------------------------------- '''

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
            ('absconding', 'Absconding'),
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


''' ------------------------------------------- Clinet - PROJECT AREA ------------------------------------------- '''
class Project(models.Model):
    name = models.CharField(max_length=100)  # Project name
    description = models.TextField()  # Description of the project
    deadline = models.DateField()  # Deadline for the project
    status = models.CharField(max_length=20, choices=[('Completed', 'Completed'), ('In Progress', 'In Progress'), ('Pending', 'Pending')])  # Status of the project
    created_at = models.DateTimeField(auto_now_add=True)  # Time when the project was created
    updated_at = models.DateTimeField(auto_now=True)  # Time when the project was last updated

    def __str__(self):
        return self.name

    def is_overdue(self):
        return self.deadline < timezone.now().date() and self.status != 'Completed'

    def remaining_days(self):
        """Calculate the number of days left until the deadline."""
        return (self.deadline - timezone.now().date()).days

    def is_completed(self):
        """Check if the project has been marked as completed."""
        return self.status == 'Completed'


# ProjectAssignment model to assign users to projects
class ProjectAssignment(models.Model):
    project = models.ForeignKey(Project, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    assigned_date = models.DateField(auto_now_add=True)
    hours_worked = models.FloatField(default=0.0)
    role_in_project = models.CharField(
        max_length=50, 
        choices=[('Manager', 'Manager'), ('Employee', 'Employee'), ('Support', 'Support'),
                 ('Appraisal', 'Appraisal'), ('QC', 'QC')],
        default='Employee'
    )
    end_date = models.DateField(null=True, blank=True)  # Soft delete field
    is_active = models.BooleanField(default=True)  # Soft delete indicator

    def __str__(self):
        return f"{self.user.username} assigned to {self.project.name}"

    def get_total_hours(self):
        # Calculate total hours worked, considering the current hours worked and any additional logic.
        return self.hours_worked

    def update_hours(self, hours):
        """Method to update hours worked for the project assignment."""
        if hours < 0:
            raise ValueError("Hours worked cannot be negative")
        self.hours_worked += hours
        self.save()


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
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='timesheets')  # Linked to Project
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
        return f"Timesheet for {self.project.name} - {self.week_start_date}"

    class Meta:
        unique_together = ('user', 'week_start_date', 'project_name', 'task_name')  # Corrected field name 'emp_id' to 'user'
        ordering = ['-week_start_date']  # Orders the entries by date (latest first)


""" ------------------ LEAVE AREA ------------------ """

from django.db import models
from django.contrib.auth.models import User

class LeaveRequest(models.Model):
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

    user= models.ForeignKey(User, on_delete=models.CASCADE)
    leave_type = models.CharField(max_length=50, choices=LEAVE_TYPES)
    start_date = models.DateField()
    end_date = models.DateField()
    leave_days = models.IntegerField()
    reason = models.TextField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Pending')
    approver = models.ForeignKey(
        User, related_name='leave_approvals', on_delete=models.SET_NULL, null=True, blank=True
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Leave Request by {self.emp_id.username} for {self.leave_type}"

    def calculate_leave_days(self):
        """Calculate leave days based on start and end dates."""
        if self.start_date and self.end_date:
            self.leave_days = (self.end_date - self.start_date).days + 1
            self.save()

class LeaveBalance(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    total_leave = models.IntegerField(default=18)
    consumed_leave = models.IntegerField(default=0)
    applied_leave = models.IntegerField(default=0)
    balance_leaves = models.IntegerField(default=18)
    pending_for_approval_leaves = models.IntegerField(default=0)
    loss_of_pay_leaves = models.IntegerField(default=0)
    status = models.CharField(max_length=50, default='Open')

    def __str__(self):
        return f"Leave Balance for {self.emp_id.username}"

    def update_balance(self):
        """Update the balance based on consumed and pending leaves."""
        self.balance_leaves = self.total_leave - self.consumed_leave - self.pending_for_approval_leaves
        if self.balance_leaves < 0:
            self.loss_of_pay_leaves = abs(self.balance_leaves)
            self.balance_leaves = 0
        else:
            self.loss_of_pay_leaves = 0
        self.save()

    
'''-------------------- CHAT AREA -------------------'''


class Chat(models.Model):
    participants = models.ManyToManyField(User)
    created_at = models.DateTimeField(auto_now_add=True)


class Message(models.Model):
    chat = models.ForeignKey(Chat, on_delete=models.CASCADE, related_name="messages")
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name="sent_messages")
    recipient = models.ForeignKey(User, on_delete=models.CASCADE, related_name="received_messages")
    content = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)


'''-------------------------------- BREAK AREA -----------------------'''

class Break(models.Model):
    SHIFT_CHOICES = [
        ('day', 'Day Shift'),
        ('night', 'Night Shift'),
    ]
    BREAK_TYPE_CHOICES = [
        ('tea1', 'Tea Break 1'),
        ('lunch_dinner', 'Lunch/Dinner Break'),
        ('tea2', 'Tea Break 2'),
    ]
    
    employee = models.ForeignKey(User, on_delete=models.CASCADE, related_name='breaks')
    break_type = models.CharField(max_length=20, choices=BREAK_TYPE_CHOICES)
    shift = models.CharField(max_length=10, choices=SHIFT_CHOICES)
    start_time = models.DateTimeField()
    end_time = models.DateTimeField(null=True, blank=True)
    reason = models.TextField(null=True, blank=True)  # Added reason field
    created_at = models.DateTimeField(auto_now_add=True)

    def duration(self):
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds() / 60  # duration in minutes
        return None

    def __str__(self):
        return f"{self.employee.username} - {self.break_type} ({self.shift})"
