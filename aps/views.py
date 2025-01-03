from django.shortcuts import render
from django.contrib.auth.models import User, Group
from .models import (UserSession, ITSupportTicket, Attendance, SystemError, 
                    UserComplaint, FailedLoginAttempt, PasswordChange, 
                    RoleAssignmentAudit, FeatureUsage, SystemUsage, 
                    Timesheet, LeaveRequest, LeaveBalance, Project, ProjectAssignment,
                    Message, Chat)
from django.db.models import Q
from datetime import datetime, timedelta, date
from django.utils import timezone
from django.contrib import messages
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required, user_passes_test
from .helpers import is_user_in_group
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
import json


''' ------------------ ROLE-BASED CHECKS ------------------ '''

def is_admin(user):
    """Check if the user belongs to the 'Admin' group."""
    return user.groups.filter(name="Admin").exists()

def is_hr(user):
    """Check if the user belongs to the 'HR' group."""
    return user.groups.filter(name="HR").exists()

def is_manager(user):
    """Check if the user belongs to the 'Manager' group."""
    return user.groups.filter(name="Manager").exists()

def is_employee(user):
    """Check if the user belongs to the 'Employee' group."""
    return user.groups.filter(name="Employee").exists()


''' ----------------- COMMON AREA ----------------- '''
@login_required
def reset_password(request):
    if request.method == 'POST':
        current_password = request.POST.get('current_pwd')
        new_password = request.POST.get('new_pwd')
        confirm_password = request.POST.get('confirm_pwd')

        # Check if new password matches confirm password
        if new_password != confirm_password:
            messages.error(request, "New password and confirm password do not match.")
            return redirect('reset_password')

        # Authenticate the current password to ensure the user is correct
        user = authenticate(username=request.user.username, password=current_password)
        if user is not None:
            # Password change logic
            user.set_password(new_password)
            user.save()

            # Update session authentication hash to prevent logout after password change
            update_session_auth_hash(request, user)

            messages.success(request, "Your password has been successfully updated.")
            return redirect('home')  # Redirect to the home page or any other page after reset
        else:
            messages.error(request, "Incorrect current password.")
            return redirect('reset_password')
    
    return render(request, 'reset_password.html')

# Create your views here.

# Home View (Redirects to login page)
def home_view(request):
    return redirect('login')


# Login View
def login_view(request):
    if request.method == "POST":
        username = request.POST.get('username')
        password = request.POST.get('password')

        try:
            # Check if the user exists
            user = User.objects.get(username=username)

            # Authenticate the user
            user = authenticate(request, username=username, password=password)

            if user is not None:
                login(request, user)
                return redirect('dashboard')
            else:
                return render(request, 'login.html', {'error': 'Invalid username or password'})

        except User.DoesNotExist:
            return render(request, 'login.html', {'error': 'Invalid username or password'})
        except Exception as e:
            return render(request, 'login.html', {'error': f'An error occurred: {str(e)}'})

    return render(request, 'login.html')


# Logout View
from django.http import JsonResponse

def logout_view(request):
    try:
        logout(request)
        return redirect('login')
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': f'An error occurred: {str(e)}'}, status=500)


# Set Password View
def set_password_view(request, username):
    if request.method == "POST":
        try:
            new_password = request.POST.get('new_password')
            confirm_password = request.POST.get('confirm_password')
            first_name = request.POST.get('first_name')
            last_name = request.POST.get('last_name')
            email = request.POST.get('email')

            if new_password != confirm_password:
                return render(
                    request,
                    'set_password.html',
                    {
                        'error': 'Passwords do not match',
                        'username': username,
                        'first_name': first_name,
                        'last_name': last_name,
                        'email': email
                    }
                )

            user = User.objects.get(username=username)
            user.set_password(new_password)
            user.first_name = first_name
            user.last_name = last_name
            user.email = email
            user.save()

            return redirect('login')

        except User.DoesNotExist:
            return render(request, 'set_password.html', {'error': 'User does not exist', 'username': username})
        except Exception as e:
            return render(request, 'set_password.html', {'error': f'An error occurred: {str(e)}'})

    return render(request, 'set_password.html', {'username': username})



'''---------------------------------   DASHBOARD VIEW ----------------------------------'''
from django.shortcuts import render
from .models import Attendance

# Function to get attendance stats
def get_attendance_stats(user):
    # Calculate total days, present days, and absent days
    total_days = Attendance.objects.filter(user=user).count()
    present_days = Attendance.objects.filter(user=user, status="Present").count()
    absent_days = Attendance.objects.filter(user=user, status="Absent").count()

    # Calculate attendance percentage
    attendance_percentage = round((present_days / total_days) * 100, 2) if total_days > 0 else 0

    # Calculate attendance change (e.g., compare with previous period)
    previous_attendance = Attendance.objects.filter(user=user, date__lt=user.date_joined).last()
    attendance_change = attendance_percentage - (previous_attendance.percentage if previous_attendance else 0)

    return {
        'attendance_percentage': attendance_percentage,
        'attendance_change': attendance_change,
        'total_present': present_days,
        'total_absent': absent_days,
        'change_display': abs(attendance_change) if attendance_change < 0 else attendance_change
    }

# Main dashboard view
@login_required
def dashboard_view(request):
    user = request.user

    # Get data for the attendance card
    attendance_data = get_attendance_stats(user)

    # Context for the dashboard view (other cards' data can be added here)
    context = {
        'attendance': attendance_data,
        # Add other cards' data as needed
    }

    return render(request, 'dashboard.html', context)



''' --------------------------------------------------------- ADMIN AREA --------------------------------------------------------- '''
# Helper function to check if the user belongs to the Admin group
def is_admin(user):
    """Check if the user belongs to the Admin group using Group model."""
    admin_group_id = 1  # Admin group ID from auth_group table
    return user.groups.filter(id=admin_group_id).exists()


from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required, user_passes_test
from django.db.models import Q
from django.utils import timezone
from django.contrib import messages
from datetime import datetime, timedelta

# Helper function to check if the user is an admin
def is_admin(user):
    return user.is_authenticated and user.is_staff

from django.contrib.auth.decorators import login_required, user_passes_test
from django.shortcuts import render

def is_admin(user):
    """Check if the user has admin privileges."""
    return user.groups.filter(name='Admin').exists()

@login_required  # Ensure the user is logged in
@user_passes_test(is_admin)  # Ensure the user is an admin
def report_view(request):
    """Main report navigation view."""
    # Navigation items for the report dashboard
    nav_items = [
        {
            'id': 'featureusage', 
            'name': 'Feature Usage', 
            'icon': 'fas fa-chart-line',
            'description': 'Insights into how features are being used.',
        },
        {
            'id': 'projects', 
            'name': 'Projects', 
            'icon': 'fas fa-project-diagram',
            'description': 'Detailed overview of ongoing and completed projects.',
        },
        {
            'id': 'systemerrors', 
            'name': 'System Errors', 
            'icon': 'fas fa-exclamation-triangle',
            'description': 'Log and analyze system errors.',
        },
        {
            'id': 'systemusage', 
            'name': 'System Usage', 
            'icon': 'fas fa-desktop',
            'description': 'Track system performance metrics and user activity.',
        },
    ]
    
    # Additional sections for the report dashboard
    sections = [
        {
            "title": "Feature Usage",
            "description": "This section provides insights into how features are being used within the platform.",
            "content": "Coming soon...",
        },
        {
            "title": "Projects Report",
            "description": "Detailed overview of all ongoing and completed projects.",
            "content": "Coming soon...",
        },
        {
            "title": "System Errors",
            "description": "Log and analyze system errors to ensure smooth platform performance.",
            "content": "Coming soon...",
        },
        {
            "title": "System Usage",
            "description": "Track overall system usage, including performance metrics and user activity.",
            "content": "Coming soon...",
        },
    ]
    
    return render(request, 'components/admin/report.html', {'nav_items': nav_items, 'sections': sections})

# View for Feature Usage Information

@login_required
@user_passes_test(is_admin)
def feature_usage_view(request):
    """View to display feature usage details."""
    try:
        feature_usages = FeatureUsage.objects.all().order_by('-usage_count')
        return render(request, 'components/admin/reports/feature_usage.html', {'feature_usages': feature_usages})

    except Exception as e:
        messages.error(request, f"An error occurred while fetching feature usage data: {str(e)}")
        return redirect('dashboard')


@login_required
@user_passes_test(is_admin)
def projects_report_view(request):
    """View to display projects report."""
    return render(request, 'components/admin/reports/projects_report.html')


@login_required
@user_passes_test(is_admin)
def system_error_view(request):
    """View to display system errors."""
    try:
        system_errors = SystemError.objects.all().order_by('-error_time')
        return render(request, 'components/admin/reports/system_error.html', {'system_errors': system_errors})

    except Exception as e:
        messages.error(request, f"An error occurred while fetching system errors: {str(e)}")
        return redirect('dashboard')


@login_required
@user_passes_test(is_admin)
def system_usage_view(request):
    """View to display system usage details."""
    try:
        system_usages = SystemUsage.objects.all().order_by('-peak_time_start')
        return render(request, 'components/admin/reports/system_usage.html', {'system_usages': system_usages})

    except Exception as e:
        messages.error(request, f"An error occurred while fetching system usage data: {str(e)}")
        return redirect('dashboard')

'''' -------------- usersession ---------------'''

@login_required
@user_passes_test(is_admin)
def user_sessions_view(request):
    """View to display user sessions, accessible only by admins."""
    try:
        # Get filter parameters from GET request
        username = request.GET.get('username', '')
        start_date = request.GET.get('start_date', '')
        end_date = request.GET.get('end_date', '')
        working_hours = request.GET.get('working_hours', None)  # Filter for working hours in format "H:M"

        filters = Q()

        # Apply username filter if provided
        if username:
            filters &= Q(user__username__icontains=username)
        
        # Apply date range filter if both start_date and end_date are provided
        if start_date and end_date:
            try:
                # Parse the start and end dates
                start_date = datetime.strptime(start_date, "%Y-%m-%d").date()
                end_date = datetime.strptime(end_date, "%Y-%m-%d").date()

                # Add date range filter
                filters &= Q(login_time__date__range=[start_date, end_date])
            except ValueError:
                messages.error(request, "Invalid date format. Please use YYYY-MM-DD.")
        
        # Apply the working hours filter if provided in the format "H:M"
        if working_hours:
            try:
                # Split the input value into hours and minutes
                hours, minutes = map(int, working_hours.split(":"))

                # Convert hours and minutes to timedelta in seconds
                total_seconds = hours * 3600 + minutes * 60
                filters &= Q(working_hours__gte=timedelta(seconds=total_seconds))
            except ValueError:
                messages.error(request, "Invalid working hours format. Please use H:M.")

        # Query the filtered sessions
        sessions = UserSession.objects.filter(filters).order_by('-login_time')

        # Convert login_time and logout_time to IST
        for session in sessions:
            if session.login_time:
                session.login_time_ist = timezone.localtime(session.login_time)  # Convert to IST
            if session.logout_time:
                session.logout_time_ist = timezone.localtime(session.logout_time)  # Convert to IST

        return render(request, 'components/admin/user_sessions.html', {'sessions': sessions})

    except Exception as e:
        messages.error(request, f"An error occurred: {str(e)}")
        return redirect('dashboard')



@login_required
@user_passes_test(is_admin)
def ticket_detail(request, ticket_id):
    """View to show details of a specific ticket."""
    try:
        ticket = get_object_or_404(ITSupportTicket, ticket_id=ticket_id)  # Correct lookup field
        return render(request, 'components/admin/ticket_detail.html', {'ticket': ticket})

    except Exception as e:
        messages.error(request, f"An error occurred: {str(e)}")
        return redirect('it_support_admin')


@login_required
@user_passes_test(is_admin)
def update_ticket(request, ticket_id):
    """View to update the status of a specific ticket."""
    try:
        ticket = get_object_or_404(ITSupportTicket, ticket_id=ticket_id)  # Correct lookup field
        if request.method == 'POST':
            status = request.POST.get('status')
            if status in dict(ITSupportTicket.STATUS_CHOICES):
                ticket.status = status
                ticket.save()
                return redirect('ticket_detail', ticket_id=ticket.ticket_id)
        return render(request, 'components/admin/update_ticket.html', {'ticket': ticket})

    except Exception as e:
        messages.error(request, f"An error occurred while updating the ticket: {str(e)}")
        return redirect('ticket_detail', ticket_id=ticket_id)
    
@login_required
@user_passes_test(is_admin)
def it_support_admin(request):
    """IT Support Admin view to manage tickets and system errors."""
    try:
        tickets = ITSupportTicket.objects.all()
        context = {
            'open_tickets': tickets.filter(status='Open').count(),
            'in_progress_tickets': tickets.filter(status='In Progress').count(),
            'resolved_tickets': tickets.filter(status='Resolved').count(),
            'tickets': tickets.order_by('-created_at'),
        }
        return render(request, 'components/admin/it_support.html', context)

    except Exception as e:
        messages.error(request, f"An error occurred while fetching tickets: {str(e)}")
        return redirect('dashboard')


@login_required
@user_passes_test(is_admin)
def ticket_detail(request, ticket_id):
    """View to show details of a specific ticket."""
    try:
        ticket = get_object_or_404(ITSupportTicket, ticket_id=ticket_id)
        return render(request, 'components/admin/ticket_detail.html', {'ticket': ticket})

    except Exception as e:
        messages.error(request, f"An error occurred: {str(e)}")
        return redirect('it_support_admin')



# View for System Usage Information
@login_required
@user_passes_test(is_admin)
def system_usage_view(request):
    """View to display system usage details."""
    try:
        system_usages = SystemUsage.objects.all().order_by('-peak_time_start')
        return render(request, 'components/admin/system_usage.html', {'system_usages': system_usages})

    except Exception as e:
        messages.error(request, f"An error occurred while fetching system usage data: {str(e)}")
        return redirect('dashboard')



# View for Password Changes
@login_required
@user_passes_test(is_admin)
def password_change_view(request):
    """View to display password change logs."""
    try:
        password_changes = PasswordChange.objects.all().order_by('-change_time')
        return render(request, 'components/admin/password_change.html', {'password_changes': password_changes})

    except Exception as e:
        messages.error(request, f"An error occurred while fetching password change logs: {str(e)}")
        return redirect('dashboard')


# View for Role Assignment Audit
@login_required
@user_passes_test(is_admin)
def role_assignment_audit_view(request):
    """View to display role assignment audit logs."""
    try:
        role_assignments = RoleAssignmentAudit.objects.all().order_by('-assigned_date')
        return render(request, 'components/admin/role_assignment_audit.html', {'role_assignments': role_assignments})

    except Exception as e:
        messages.error(request, f"An error occurred while fetching role assignment audit logs: {str(e)}")
        return redirect('dashboard')



''' --------------------------------------------------------- EMPLOYEE AREA --------------------------------------------------------- '''

def is_employee(user):
    """Check if the user belongs to the Employee group."""
    return user.groups.filter(name='Employee').exists()


# IT Support View

@login_required
def it_support_home(request):
    return render(request, 'components/employee/it_support.html')

@login_required
def create_ticket(request):
    if request.method == 'POST':
        issue_type = request.POST.get('issue_type')
        description = request.POST.get('description')

        if not issue_type or not description:
            messages.error(request, "Issue Type and Description are required.")
            return redirect('create_ticket')

        ITSupportTicket.objects.create(
            user=request.user,
            issue_type=issue_type,
            description=description,
            status='Open'
        )
        messages.success(request, "Your ticket has been created successfully.")
        return redirect('it_support_home')

    return render(request, 'components/employee/create_ticket.html')

@login_required
def change_password(request):
    if request.method == 'POST':
        # Logic for password change
        messages.success(request, "Password changed successfully.")
        return redirect('it_support_home')
    return render(request, 'components/employee/change_password.html')
# Attendance View

''' ---------------------------------------- TIMESHEET AREA ---------------------------------------- '''

@login_required
def timesheet_view(request):
    if request.method == "POST":
        # Handle form submission
        try:
            # Get the submitted data
            week_start_date = request.POST.get('week_start_date')
            project_names = request.POST.getlist('project_name[]')
            task_names = request.POST.getlist('task_name[]')
            hours = request.POST.getlist('hours[]')

            # Validate that project names, task names, and hours lists are all the same length
            if len(project_names) != len(task_names) or len(task_names) != len(hours):
                messages.error(request, "Project name, task name, and hours should have the same number of entries.")
                return redirect('aps:timesheet')

            # Create the Timesheet objects
            for project_name, task_name, hour in zip(project_names, task_names, hours):
                timesheet = Timesheet(
                    user=request.user,
                    week_start_date=week_start_date,
                    project_name=project_name,
                    task_name=task_name,
                    hours=float(hour)
                )
                timesheet.save()

            messages.success(request, "Timesheet submitted successfully!")
            return redirect('aps:timesheet')

        except Exception as e:
            messages.error(request, f"An error occurred: {e}")
            return redirect('aps:timesheet')

    else:
        # Display the form on GET request
        today = timezone.now().date()

        # Fetch the timesheet history for the logged-in user
        timesheet_history = Timesheet.objects.filter(user=request.user).order_by('-week_start_date')

        return render(request, 'components/employee/timesheet.html', {'today': today, 'timesheet_history': timesheet_history})

@login_required
def manager_view_timesheets(request):
    if not request.user.groups.filter(name='Manager').exists():
        messages.error(request, "You do not have permission to view this page.")
        return redirect('aps:dashboard')

    # Fetch all timesheets for managers to review
    timesheets = Timesheet.objects.all().order_by('-week_start_date')

    # Calculate summary metrics
    total_hours = sum(ts.hours for ts in timesheets)
    active_projects = len(set(ts.project_name for ts in timesheets))
    completion_rate = 85  # Placeholder - implement actual calculation

    # Pass the timesheet data as a list of dictionaries (no need for JSON)
    context = {
        'timesheets': timesheets,
        'total_hours': total_hours,
        'active_projects': active_projects,
        'completion_rate': completion_rate,
    }
    return render(request, 'components/manager/view_timesheets.html', context)


''' ---------------------------------------- LEAVE AREA ---------------------------------------- '''

@login_required
@user_passes_test(is_employee)  # Only employees can access leave request page
def leave_request_view(request):
    """View for employees to submit leave requests"""
    if request.method == 'POST':
        # Extracting data from POST request
        leave_type = request.POST.get('leave_type')
        start_date = request.POST.get('start_date')
        end_date = request.POST.get('end_date')
        leave_days = int(request.POST.get('leave_days'))
        reason = request.POST.get('reason')

        # Create a new leave request instance
        leave_request = LeaveRequest(
            emp_id=request.user,  # Assign the employee to the leave request
            leave_type=leave_type,
            start_date=start_date,
            end_date=end_date,
            leave_days=leave_days,
            reason=reason
        )
        leave_request.save()

        # Update leave balance
        leave_balance = LeaveBalance.objects.get(emp_id=request.user)
        leave_balance.applied_leave += leave_days
        leave_balance.balance_leaves -= leave_days
        leave_balance.save()

        return redirect('aps_employee:view_leave_balance')  # Redirect to view balance after submission

    return render(request, 'components/employee/leave_request.html')

@login_required
@user_passes_test(is_employee)
def view_leave_balance(request):
    """View for employees to see their leave balance"""
    leave_balance = LeaveBalance.objects.get(emp_id=request.user)
    return render(request, 'components/employee/view_leave_balance.html', {'leave_balance': leave_balance})

@login_required
@user_passes_test(is_admin)  # Admin can approve leaves for all
def approve_leave(request, leave_id):
    """Admin view to approve leave requests"""
    leave_request = get_object_or_404(LeaveRequest, id=leave_id)
    leave_balance = LeaveBalance.objects.get(emp_id=leave_request.emp_id)

    if request.method == 'POST':
        leave_request.status = 'Approved'
        leave_request.save()

        leave_balance.pending_for_approval_leaves -= leave_request.leave_days
        leave_balance.applied_leave += leave_request.leave_days
        leave_balance.balance_leaves -= leave_request.leave_days
        leave_balance.save()

        return redirect('aps_admin:view_leave_requests')

        return render(request, 'components/admin/approve_leave.html', {'leave_request': leave_request})

@login_required
@user_passes_test(is_hr)  # HR can approve leaves for special cases
def approve_leave_hr(request, leave_id):
    """HR view to approve leave requests"""
    leave_request = get_object_or_404(LeaveRequest, id=leave_id)
    leave_balance = LeaveBalance.objects.get(emp_id=leave_request.emp_id)

    if request.method == 'POST':
        leave_request.status = 'Approved'
        leave_request.save()

        leave_balance.pending_for_approval_leaves -= leave_request.leave_days
        leave_balance.applied_leave += leave_request.leave_days
        leave_balance.balance_leaves -= leave_request.leave_days
        leave_balance.save()

        return redirect('aps_hr_manager:view_leave_requests')

    return render(request, 'components/hr_manager/approve_leave.html', {'leave_request': leave_request})

@login_required
@user_passes_test(is_manager)  # Manager can approve leave requests for their team
def approve_leave_manager(request, leave_id):
    """Manager view to approve leave requests for their team"""
    leave_request = get_object_or_404(LeaveRequest, id=leave_id)

    # Check if the leave request is for an employee in the manager's team
    if leave_request.emp_id.manager != request.user:
        raise Http404("You cannot approve leaves for this employee.")

    leave_balance = LeaveBalance.objects.get(emp_id=leave_request.emp_id)

    if request.method == 'POST':
        leave_request.status = 'Approved'
        leave_request.save()

        leave_balance.pending_for_approval_leaves -= leave_request.leave_days
        leave_balance.applied_leave += leave_request.leave_days
        leave_balance.balance_leaves -= leave_request.leave_days
        leave_balance.save()

        return redirect('aps_manager:view_leave_requests')

    return render(request, 'components/manager/approve_leave.html', {'leave_request': leave_request})

@login_required
@user_passes_test(is_admin)  # Admin can view all leave requests
def view_leave_requests_admin(request):
    """Admin view to see all leave requests"""
    leave_requests = LeaveRequest.objects.all()
    return render(request, 'components/admin/view_leave_requests.html', {'leave_requests': leave_requests})

@login_required
@user_passes_test(is_hr)  # HR can view all leave requests
def view_leave_requests_hr(request):
    """HR view to see all leave requests"""
    leave_requests = LeaveRequest.objects.all()
    return render(request, 'components/hr_manager/view_leave_requests.html', {'leave_requests': leave_requests})

@login_required
@user_passes_test(is_manager)  # Manager can view only their team's leave requests
def view_leave_requests_manager(request):
    """Manager view to see team leave requests"""
    leave_requests = LeaveRequest.objects.filter(emp_id__manager=request.user)
    return render(request, 'components/manager/view_leave_requests.html', {'leave_requests': leave_requests})

@login_required
@user_passes_test(is_employee)
def view_leave_balance_employee(request):
    """Employee can view their own leave balance"""
    leave_balance = LeaveBalance.objects.get(emp_id=request.user)
    return render(request, 'aps/employee/view_leave_balance.html', {'leave_balance': leave_balance})




''' ------------------------------------------- PROJECT AREA ------------------------------------------- '''

# Helper function to check if the user is an admin
def is_admin(user):
    return user.groups.filter(name='Admin').exists()

# Project management dashboard (Admin only)
@login_required
@user_passes_test(is_admin)
def project_management(request):
    return render(request, 'components/admin/projects.html')

# View for managing a project (creating, editing, viewing)
@login_required
@user_passes_test(is_admin)
def project_view(request, project_id=None):
    if project_id:
        project = get_object_or_404(Project, id=project_id)
    else:
        project = None
    return render(request, 'components/admin/project/view_project.html', {'project': project})

# Admin can create a new project
@login_required
@user_passes_test(is_admin)
def add_project(request):
    """View for adding a new project."""
    class ProjectForm(forms.ModelForm):
        class Meta:
            model = Project
            fields = ['name', 'description', 'deadline', 'status']

    if request.method == 'POST':
        form = ProjectForm(request.POST)
        if form.is_valid():
            project = form.save()
            return redirect('view_project', project_id=project.id)
    else:
        form = ProjectForm()

    return render(request, 'components/admin/project/add_project.html', {'form': form})

# Admin can assign a manager to a project
@login_required
@user_passes_test(is_admin)
def assign_manager(request, project_id):
    project = get_object_or_404(Project, id=project_id)
    if request.method == 'POST':
        manager_id = request.POST.get('manager')
        manager = get_object_or_404(User, id=manager_id)
        assignment = ProjectAssignment.objects.create(project=project, user=manager, role_in_project='Manager')
        return redirect('view_project', project_id=project.id)

    available_managers = User.objects.filter(groups__name="Manager")
    return render(request, 'components/admin/project/assign_manager.html', {'project': project, 'available_managers': available_managers})

# Admin or Manager can assign employees to a project
@login_required
@user_passes_test(lambda user: user.groups.filter(name__in=['Admin', 'Manager']).exists())
def assign_employee(request, project_id):
    project = get_object_or_404(Project, id=project_id)

    class ProjectAssignmentForm(forms.ModelForm):
        class Meta:
            model = ProjectAssignment
            fields = ['user', 'role_in_project']

    if request.method == 'POST':
        form = ProjectAssignmentForm(request.POST)
        if form.is_valid():
            employee = form.cleaned_data['user']
            role = form.cleaned_data['role_in_project']
            ProjectAssignment.objects.create(project=project, user=employee, role_in_project=role)
            return redirect('view_project', project_id=project.id)
    else:
        form = ProjectAssignmentForm()

    available_employees = User.objects.filter(groups__name="Employee")
    return render(request, 'components/admin/project/assign_employee.html', {'project': project, 'form': form, 'available_employees': available_employees})

# Employees log their worked hours on a project
@login_required
@user_passes_test(lambda user: user.groups.filter(name__in=['Admin', 'Manager', 'Employee']).exists())
def log_hours(request, project_assignment_id):
    assignment = get_object_or_404(ProjectAssignment, id=project_assignment_id)
    if request.method == 'POST':
        try:
            hours_worked = float(request.POST.get('hours_worked'))
            if hours_worked <= 0:
                raise ValueError("Hours worked must be a positive number.")
            assignment.update_hours(hours_worked)
            return redirect('view_project', project_id=assignment.project.id)
        except (ValueError, TypeError):
            # Handle the error (e.g., show a message to the user)
            pass

    return render(request, 'components/admin/project/log_hours.html', {'assignment': assignment})

# Admin and Manager can view project details, including overdue status
@login_required
@user_passes_test(lambda user: user.groups.filter(name__in=['Admin', 'Manager']).exists())
def view_project(request, project_id):
    project = get_object_or_404(Project, id=project_id)
    overdue = project.is_overdue()
    assignments = ProjectAssignment.objects.filter(project=project)
    return render(request, 'components/admin/project/view_project.html', {'project': project, 'overdue': overdue, 'assignments': assignments})

# Admin and Manager can view all projects and their status
@login_required
@user_passes_test(lambda user: user.groups.filter(name__in=['Admin', 'Manager']).exists())
def all_projects(request):
    projects = Project.objects.all()
    return render(request, 'components/admin/project/all_projects.html', {'projects': projects})



''' ------------------------------------------- ATTENDACE AREA ------------------------------------------- '''

# aps/views.py

from django.http import JsonResponse, HttpResponse
from aps.tasks import calculate_daily_attendance
from django.contrib.auth.decorators import login_required, user_passes_test
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from .models import Attendance
from django.template.loader import render_to_string
import csv
import openpyxl
from datetime import datetime

# Trigger Celery task for daily attendance calculation
def trigger_attendance_calculation(request):
    calculate_daily_attendance()  # Trigger the Celery task asynchronously
    return JsonResponse({'message': 'Attendance calculation triggered.'})

# Employee Attendance View
@login_required
def employee_attendance_view(request):
    # Get the user's attendance data
    user_attendance = Attendance.objects.filter(user=request.user).order_by('-date')
    
    # Pagination setup (show 10 records per page)
    paginator = Paginator(user_attendance, 10)
    page = request.GET.get('page')
    
    try:
        records = paginator.get_page(page)
    except EmptyPage:
        records = paginator.page(paginator.num_pages)
    except PageNotAnInteger:
        records = paginator.page(1)

    # Attendance statistics
    total_present = user_attendance.filter(status='Present').count()
    total_absent = user_attendance.filter(status='Absent').count()
    total_leave = user_attendance.filter(status='On Leave').count()
    total_wfh = user_attendance.filter(status='Work From Home').count()

    return render(request, 'components/employee/employee_attendance.html', {
        'total_present': total_present,
        'total_absent': total_absent,
        'total_leave': total_leave,
        'total_wfh': total_wfh,
        'records': records
    })

# Manager Attendance View
@login_required
@user_passes_test(is_manager)
def manager_attendance_view(request):
    # Prefetching related user manager data for efficiency
    team_attendance = Attendance.objects.filter(user__manager=request.user).select_related('user').order_by('-date')
    
    # Pagination setup
    paginator = Paginator(team_attendance, 10)
    page = request.GET.get('page')
    
    try:
        team_records = paginator.get_page(page)
    except EmptyPage:
        team_records = paginator.page(paginator.num_pages)
    except PageNotAnInteger:
        team_records = paginator.page(1)

    return render(request, 'components/manager/manager_attendance.html', {'team_attendance': team_records})

# HR Attendance View
@login_required
@user_passes_test(is_hr)
def hr_attendance_view(request):
    # Optimized query using select_related
    all_attendance = Attendance.objects.select_related('user').order_by('-date')

    # Filters
    username_filter = request.GET.get('username', '')
    status_filter = request.GET.get('status', '')
    date_filter = request.GET.get('date', '')

    if username_filter:
        all_attendance = all_attendance.filter(user__username__icontains=username_filter)
    if status_filter:
        all_attendance = all_attendance.filter(status=status_filter)
    if date_filter:
        all_attendance = all_attendance.filter(date=date_filter)

    # Handle export requests before pagination
    export_type = request.GET.get('export')
    if export_type == 'csv':
        return export_attendance_csv(all_attendance)
    elif export_type == 'excel':
        return export_attendance_excel(all_attendance)

    # Pagination
    paginator = Paginator(all_attendance, 10)
    page = request.GET.get('page', 1)
    try:
        all_records = paginator.get_page(page)
    except (PageNotAnInteger, EmptyPage):
        all_records = paginator.page(1)

    # Attendance summary counts
    present_count = all_attendance.filter(status='Present').count()
    absent_count = all_attendance.filter(status='Absent').count()
    leave_count = all_attendance.filter(status='On Leave').count()

    return render(request, 'components/hr/hr_admin_attendance.html', {
        'summary': all_records,
        'username_filter': username_filter,
        'status_filter': status_filter,
        'date_filter': date_filter,
        'present_count': present_count,
        'absent_count': absent_count,
        'leave_count': leave_count,
    })

# Export attendance as CSV
def export_attendance_csv(queryset):
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="attendance.csv"'

    writer = csv.writer(response)
    writer.writerow(['Employee', 'Username', 'Status', 'Date'])

    # Fetching required fields only
    records = queryset.values(
        'user__first_name', 'user__last_name', 'user__username', 'status', 'date'
    )
    for record in records:
        writer.writerow([
            f"{record['user__first_name']} {record['user__last_name']}",
            record['user__username'],
            record['status'],
            record['date'].strftime('%Y-%m-%d'),
        ])
    return response

# Export attendance as Excel
def export_attendance_excel(queryset):
    response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
    response['Content-Disposition'] = 'attachment; filename="attendance.xlsx"'

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Attendance"
    ws.append(['Employee', 'Username', 'Status', 'Date'])

    # Fetching required fields only
    records = queryset.values(
        'user__first_name', 'user__last_name', 'user__username', 'status', 'date'
    )
    for record in records:
        ws.append([
            f"{record['user__first_name']} {record['user__last_name']}",
            record['user__username'],
            record['status'],
            record['date'].strftime('%Y-%m-%d'),
        ])
    wb.save(response)
    return response

# Admin Attendance View
@login_required
@user_passes_test(is_admin)
def admin_attendance_view(request):
    # Get filter values from GET parameters
    username_filter = request.GET.get('username', '')
    status_filter = request.GET.get('status', '')
    date_filter = request.GET.get('date', '')

    # Filter the attendance summary based on the filters
    attendance_summary = Attendance.objects.all()

    if username_filter:
        attendance_summary = attendance_summary.filter(user__username__icontains=username_filter)

    if status_filter:
        attendance_summary = attendance_summary.filter(status=status_filter)

    if date_filter:
        try:
            date_obj = datetime.strptime(date_filter, '%Y-%m-%d').date()
            attendance_summary = attendance_summary.filter(date=date_obj)
        except ValueError:
            pass  # If the date format is incorrect, it will be ignored

    # Optimized query with selected fields
    attendance_summary = attendance_summary.values(
        'user', 'user__first_name', 'user__last_name', 'user__username', 'status', 'date'
    ).order_by('-date')

    # Pagination setup
    paginator = Paginator(attendance_summary, 10)
    page = request.GET.get('page', 1)

    try:
        summary_records = paginator.get_page(page)
    except EmptyPage:
        summary_records = paginator.page(paginator.num_pages)
    except PageNotAnInteger:
        summary_records = paginator.page(1)

    return render(request, 'components/admin/hr_admin_attendance.html', {
        'summary': summary_records,
        'username_filter': username_filter,
        'status_filter': status_filter,
        'date_filter': date_filter
    })


'''--------------------------- CHAT AREA------------------------'''
# views.py
from django.shortcuts import render
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.db import DatabaseError
from .models import User, Chat, Message, UserSession
from django.utils import timezone

@login_required
def chat_view(request):
    try:
        # Fetch users except the logged-in user
        users = User.objects.exclude(id=request.user.id)

        # Fetch the online status for each user
        users_status = [
            {
                'username': user.username,
                'status': get_user_status(user)
            }
            for user in users
        ]
    except DatabaseError as e:
        return JsonResponse({"error": f"Database error: {str(e)}"}, status=500)

    return render(request, 'components/chat/chat.html', {
        'users_status': users_status
    })

@login_required
def load_messages(request, recipient_username):
    try:
        recipient = User.objects.get(username=recipient_username)
    except User.DoesNotExist:
        return JsonResponse({"error": "User not found"}, status=404)
    except DatabaseError as e:
        return JsonResponse({"error": f"Database error: {str(e)}"}, status=500)

    try:
        # Get the chat between the logged-in user and the recipient
        chat = Chat.objects.filter(
            participants=request.user
        ).filter(
            participants=recipient
        ).first()

        if not chat:
            return JsonResponse({"error": "No chat found with the user"}, status=404)

        # Get all messages from the chat
        messages = Message.objects.filter(chat=chat).order_by('timestamp')

        message_list = [{
            'sender': message.sender.username,
            'content': message.content,
            'timestamp': message.timestamp,
        } for message in messages]

        return JsonResponse(message_list, safe=False)
    except DatabaseError as e:
        return JsonResponse({"error": f"Database error: {str(e)}"}, status=500)
    except Exception as e:
        return JsonResponse({"error": f"Unexpected error: {str(e)}"}, status=500)

@login_required
def send_message(request):
    if request.method == 'POST':
        recipient_username = request.POST.get('recipient')
        content = request.POST.get('message')

        if not recipient_username or not content:
            return JsonResponse({"error": "Invalid data, recipient or message missing"}, status=400)

        try:
            recipient = User.objects.get(username=recipient_username)
        except User.DoesNotExist:
            return JsonResponse({"error": "User not found"}, status=404)
        except DatabaseError as e:
            return JsonResponse({"error": f"Database error: {str(e)}"}, status=500)

        try:
            # Create or get the chat between the logged-in user and the recipient
            chat = Chat.objects.filter(
                participants=request.user
            ).filter(
                participants=recipient
            ).first()

            if not chat:
                chat = Chat.objects.create()

            # Add participants if not already added
            chat.participants.add(request.user, recipient)

            # Create the new message
            message = Message.objects.create(
                chat=chat,
                sender=request.user,
                recipient=recipient,
                content=content,
            )

            return JsonResponse({
                'sender': message.sender.username,
                'content': message.content,
                'timestamp': message.timestamp,
            })

        except DatabaseError as e:
            return JsonResponse({"error": f"Database error: {str(e)}"}, status=500)
        except Exception as e:
            return JsonResponse({"error": f"Unexpected error: {str(e)}"}, status=500)

    return JsonResponse({"error": "Invalid request method, expected POST"}, status=400)

def get_user_status(user):
    """Function to get the online/offline status of a user"""
    # Get the latest session of the user
    user_session = UserSession.objects.filter(user=user).last()

    if user_session and user_session.logout_time is None:
        return 'Online'
    else:
        return 'Offline'


'''----- Temeporray views -----'''

# Assign Tasks View
@login_required
def assign_tasks(request):
    # Placeholder context data
    context = {
        'title': 'Assign Tasks',
        'tasks': [],  # Example data (you can replace this with actual task data)
    }
    return render(request, 'components/manager/assign_tasks.html', context)

# Approve Leaves View
@login_required
def approve_leave(request):
    # Placeholder context data
    context = {
        'title': 'Approve Leaves',
        'leave_requests': [],  # Example data (you can replace this with actual leave request data)
    }
    return render(request, 'components/manager/approve_leave.html', context)




'''-------------------------- BREAK AREA ---------------------------'''
from django.http import JsonResponse
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.utils.timezone import now
from .models import Break
from .context_processors import is_manager, is_employee, is_hr
from datetime import timedelta
from asgiref.sync import sync_to_async  # For async compatibility

# Break Management View
@login_required
def break_management(request):
    user = request.user
    # Fetch active breaks (those not yet ended)
    active_breaks = Break.objects.filter(employee=user, end_time__isnull=True).order_by('start_time')
    print(f"Active breaks fetched: {active_breaks}")

    # Define break durations for tea breaks and lunch/dinner break
    break_durations = {
        'tea1': timedelta(minutes=10),
        'lunch_dinner': timedelta(minutes=30),
        'tea2': timedelta(minutes=10),
    }

    break_data = []
    for break_item in active_breaks:
        remaining_time = break_durations.get(break_item.break_type) - (now() - break_item.start_time)
        break_data.append({
            'break_type': break_item.get_break_type_display(),
            'start_time': break_item.start_time,
            'remaining_time': remaining_time if remaining_time > timedelta() else timedelta(),
            'break_id': break_item.id,
        })
    
    print(f"Break data: {break_data}")  # Add this line to check if break_data is populated

    return render(request, 'card/break_management.html', {'break_data': break_data})

# Async Break Start Logic
@sync_to_async
def start_break_async(user, break_type):
    active_breaks = Break.objects.filter(employee=user, end_time__isnull=True)
    if active_breaks.exists():
        last_break = active_breaks.order_by('start_time').last()
        break_order = ['tea1', 'lunch_dinner', 'tea2']
        current_break_index = break_order.index(last_break.break_type)
        if break_order.index(break_type) != current_break_index + 1:
            return JsonResponse({"error": "You must complete the previous break before starting the next one."}, status=400)

    existing_break = Break.objects.filter(employee=user, break_type=break_type, end_time__isnull=True).first()
    if existing_break:
        return JsonResponse({"error": f"You already have an active {existing_break.get_break_type_display()}."}, status=400)

    shift = 'day' if 6 <= now().hour < 18 else 'night'
    new_break = Break.objects.create(employee=user, break_type=break_type, shift=shift, start_time=now())
    return JsonResponse({"message": f"{new_break.get_break_type_display()} started successfully.", "break_id": new_break.id}, status=200)

# Start Break View
@login_required
def start_break(request, break_type):
    user = request.user

    # Ensure user has permission
    if not (is_manager(request)['is_manager'] or is_employee(request)['is_employee'] or is_hr(request)['is_hr']):
        return JsonResponse({"error": "You do not have permission to start a break."}, status=403)

    return start_break_async(user, break_type)

# End Break View
@login_required
def end_break(request, break_id):
    user = request.user

    # Restrict access to Manager, HR, or Employee roles
    if not (is_manager(request)['is_manager'] or is_employee(request)['is_employee'] or is_hr(request)['is_hr']):
        return JsonResponse({"error": "You do not have permission to end a break."}, status=403)
    
    try:
        active_break = Break.objects.get(id=break_id, employee=user, end_time__isnull=True)
        
        # End the break
        active_break.end_time = now()

        # Calculate if the break time exceeded its duration
        break_duration = {
            'tea1': timedelta(minutes=10),
            'lunch_dinner': timedelta(minutes=30),
            'tea2': timedelta(minutes=10),
        }
        
        duration = active_break.end_time - active_break.start_time
        excess_time = duration - break_duration.get(active_break.break_type, timedelta())
        
        # If the break time exceeds allowed duration, prompt for a reason
        if excess_time > timedelta():
            return JsonResponse({"message": f"Break exceeded by {excess_time}. Please provide a reason for the delay.", "break_id": break_id}, status=400)

        # Save the end time
        active_break.save()
        return JsonResponse({"message": f"{active_break.get_break_type_display()} ended successfully.", "break_id": break_id}, status=200)
    except Break.DoesNotExist:
        return JsonResponse({"error": "No active break found to end."}, status=404)

# Submit Reason for Delay View
@login_required
def submit_reason(request, break_id):
    user = request.user
    try:
        active_break = Break.objects.get(id=break_id, employee=user, end_time__isnull=True)

        # Get reason from the POST data
        reason = request.POST.get('reason')

        if not reason:
            return JsonResponse({"error": "Please provide a reason."}, status=400)

        # Store the reason in the database (assuming a reason field exists on Break model)
        active_break.reason = reason
        active_break.save()

        return JsonResponse({"message": "Reason submitted successfully."}, status=200)

    except Break.DoesNotExist:
        return JsonResponse({"error": "No active break found."}, status=404)
