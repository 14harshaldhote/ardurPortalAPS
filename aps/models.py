from django.utils import timezone
from django.contrib.auth.models import User
import pytz
from django.db import models
from django.utils.timezone import now


# User session model to track login, logout, working hours, and idle time
class UserSession(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)  # Reference to the User model
    login_time = models.DateTimeField(default=timezone.now)  # Timestamp of user login
    logout_time = models.DateTimeField(null=True, blank=True)  # Timestamp of user logout
    session_key = models.CharField(max_length=40)  # Session key to uniquely identify sessions
    working_hours = models.DurationField(null=True, blank=True)  # Total working hours during session
    idle_time = models.DurationField(null=True, blank=True)  # Idle time when no activity is detected
    last_activity = models.DateTimeField(null=True, blank=True)  # Timestamp of last activity

    def save(self, *args, **kwargs):
        """Override save method to ensure times are timezone-aware and calculate working/idle hours."""
        # Ensure login_time and logout_time are timezone-aware
        if self.login_time and not timezone.is_aware(self.login_time):
            self.login_time = timezone.make_aware(self.login_time, timezone.get_current_timezone())

        if self.logout_time and not timezone.is_aware(self.logout_time):
            self.logout_time = timezone.make_aware(self.logout_time, timezone.get_current_timezone())

        # Calculate working hours if logout_time is provided
        if self.logout_time and not self.working_hours:
            self.calculate_working_hours()

        # Calculate idle time if last_activity and logout_time are available
        if self.last_activity and self.logout_time:
            self.calculate_idle_time()

        super().save(*args, **kwargs)

    def get_login_time_in_ist(self):
        """Convert login_time to IST (Indian Standard Time)."""
        india_tz = pytz.timezone('Asia/Kolkata')
        if self.login_time:
            return timezone.localtime(self.login_time, india_tz)
        return None

    def get_logout_time_in_ist(self):
        """Convert logout_time to IST (Indian Standard Time)."""
        india_tz = pytz.timezone('Asia/Kolkata')
        if self.logout_time:
            return timezone.localtime(self.logout_time, india_tz)
        return None

    def calculate_working_hours(self):
        """Calculate working hours from login_time and logout_time."""
        if self.logout_time:
            self.working_hours = self.logout_time - self.login_time

    def calculate_idle_time(self):
        """Calculate idle time during the session if last_activity and logout_time are available."""
        if self.last_activity and self.logout_time:
            active_threshold = timezone.timedelta(minutes=5)  # Consider idle after 5 min of inactivity
            time_since_last_activity = self.logout_time - self.last_activity
            if time_since_last_activity > active_threshold:
                self.idle_time = time_since_last_activity - active_threshold
            else:
                self.idle_time = timezone.timedelta(0)

    def update_activity(self):
        """Update the last activity timestamp."""
        self.last_activity = timezone.now()
        self.save(update_fields=['last_activity'])


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


# Project model to store project-related information
class Project(models.Model):
    name = models.CharField(max_length=100)  # Project name
    description = models.TextField()  # Description of the project
    deadline = models.DateField()  # Deadline for the project
    status = models.CharField(max_length=20, choices=[('Completed', 'Completed'), ('In Progress', 'In Progress'), ('Pending', 'Pending')])  # Status of the project
    created_at = models.DateTimeField(auto_now_add=True)  # Time when the project was created

    def __str__(self):
        """Return the project name."""
        return self.name

    def is_overdue(self):
        """Check if the project is overdue based on the deadline."""
        return self.deadline < timezone.now().date() and self.status != 'Completed'


# ProjectAssignment model to assign users to projects
class ProjectAssignment(models.Model):
    project = models.ForeignKey(Project, on_delete=models.CASCADE)  # The project being assigned
    user = models.ForeignKey(User, on_delete=models.CASCADE)  # The user being assigned to the project
    assigned_date = models.DateField(auto_now_add=True)  # Date of assignment
    hours_worked = models.FloatField(default=0.0)  # Total hours worked by the user on the project
    role_in_project = models.CharField(max_length=50, choices=[('Manager', 'Manager'), ('Developer', 'Developer'), ('Support', 'Support'), ('Tester', 'Tester')])  # Role of the user in the project

    def __str__(self):
        """Return a string representation of the project assignment."""
        return f"{self.user.username} assigned to {self.project.name}"

    def get_total_hours(self):
        """Calculate total hours worked by a user on a project."""
        return self.hours_worked


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


''' ----------------- EMPLOYEE AREA ----------------- '''



class Attendance(models.Model):
    STATUS_CHOICES = [
        ('Present', 'Present'),
        ('Absent', 'Absent'),
        ('On Leave', 'On Leave'),
        ('Work From Home', 'Work From Home'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    date = models.DateField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES)
    
    def __str__(self):
        return f"{self.user.username} - {self.date} - {self.status}"
    


class Timesheet(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='timesheets')
    week_start_date = models.DateField()
    project_name = models.CharField(max_length=255)
    task_name = models.CharField(max_length=255)
    hours = models.FloatField()

    def __str__(self):
        return f"Timesheet for {self.project_name} - {self.week_start_date}"

    class Meta:
        unique_together = ('user', 'week_start_date', 'project_name', 'task_name')  # Corrected field name 'emp_id' to 'user'
        ordering = ['-week_start_date']  # Orders the entries by date (latest first)


""" ------------------ LEAVE AREA ------------------ """

class LeaveRequest(models.Model):
    LEAVE_TYPES = [
        ('Sick Leave', 'Sick Leave'),
        ('Casual Leave', 'Casual Leave'),
        ('Earned Leave', 'Earned Leave'),
        ('Loss of Pay', 'Loss of Pay'),
    ]
    emp_id = models.ForeignKey(User, on_delete=models.CASCADE)
    leave_type = models.CharField(max_length=50, choices=LEAVE_TYPES)
    start_date = models.DateField()
    end_date = models.DateField()
    leave_days = models.IntegerField()
    reason = models.TextField()

    def __str__(self):
        return f"Leave Request by {self.emp_id.username} for {self.leave_type}"

class LeaveBalance(models.Model):
    emp_id = models.OneToOneField(User, on_delete=models.CASCADE)
    total_leave = models.IntegerField(default=20)
    consumed_leave = models.IntegerField(default=0)
    applied_leave = models.IntegerField(default=0)
    balance_leaves = models.IntegerField(default=20)
    pending_for_approval_leaves = models.IntegerField(default=0)
    loss_of_pay_leaves = models.IntegerField(default=0)
    status = models.CharField(max_length=50, default='Open')

    def __str__(self):
        return f"Leave Balance for {self.emp_id.username}"