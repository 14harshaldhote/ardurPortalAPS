from django.shortcuts import render
from django.contrib.auth.models import User, Group
from .models import (UserSession, Attendance, SystemError, 
                    Support, FailedLoginAttempt, PasswordChange, 
                    RoleAssignmentAudit, FeatureUsage, SystemUsage, 
                    Timesheet, Project,ClientParticipation, ProjectAssignment,
                    Message, Chat,UserDetails)
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

    # Get data for the attendance card (as you had before)
    attendance_data = get_attendance_stats(user)

    # Retrieve all assignments where the logged-in user is assigned to any role
    assignments = ProjectAssignment.objects.filter(user=user)

    # Get the projects from the assignments
    projects = [assignment.project for assignment in assignments]

    # Context for the dashboard view
    context = {
        'attendance': attendance_data,
        'projects': projects,  # Pass the projects to the template
    }

    return render(request, 'dashboard.html', context)

''' --------------------------------------------------------- USER DETAILS AREA --------------------------------------------------------- '''

# aps/views.py

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
from django.http import HttpResponseForbidden
from .models import UserDetails
from django.contrib.auth.models import User
from datetime import datetime

# Permission check functions
def is_hr(user):
    return user.groups.filter(name='HR').exists()

def is_manager(user):
    return user.groups.filter(name='Manager').exists()

def is_employee(user):
    return user.groups.filter(name='Employee').exists()

# HR Views
@login_required
@user_passes_test(is_hr)
def hr_dashboard(request):
    """HR Dashboard to see all users and perform actions"""
    search_query = request.GET.get('search', '')
    department_filter = request.GET.get('department', '')
    status_filter = request.GET.get('status', '')
    work_location_filter = request.GET.get('work_location', '')  # Add work location filter

    # Start with all users
    users = User.objects.all()

    # Filter based on the search query
    if search_query:
        users = users.filter(
            Q(first_name__icontains=search_query) |
            Q(last_name__icontains=search_query) |
            Q(job_description__icontains=search_query) |
            Q(username__icontains=search_query)
        )

    # Filter by UserDetails department if selected
    if department_filter:
        users = users.filter(userdetails__department=department_filter)

    # Filter by employment status if selected
    if status_filter:
        users = users.filter(userdetails__employment_status=status_filter)

    # Filter by work location if selected
    if work_location_filter:
        users = users.filter(userdetails__work_location=work_location_filter)

    # Use select_related to join UserDetails to avoid additional queries
    users = users.select_related('userdetails')

    return render(request, 'components/hr/hr_dashboard.html', {
        'users': users,
        'role': 'HR'
    })

@user_passes_test(is_hr)
def hr_user_detail(request, user_id):
    # Add logging for initial request
    print(f"Accessing details for user_id: {user_id}")
    
    user = get_object_or_404(User, id=user_id)
    print(f"Accessing details for user_id after get_object_or_404: {user_id}")
    user_detail, created = UserDetails.objects.get_or_create(user=user)

    if request.method == 'POST':
        try:
            # Log the incoming request data
            print(f"Processing POST request for user_id: {user_id}")
            print("POST data received:", request.POST)

            # Validate contact number if provided
            contact_number = request.POST.get('contact_number_primary')
            if contact_number:
                if not contact_number.isdigit():
                    raise ValueError('Contact number must contain only digits.')
                if len(contact_number) != 10:
                    raise ValueError('Contact number must be exactly 10 digits.')

            # Validate Aadhar number if provided
            aadhar_number = request.POST.get('aadharno')
            if aadhar_number:
                aadhar_cleaned = aadhar_number.replace(' ', '')
                if not aadhar_cleaned.isdigit():
                    raise ValueError('Aadhar number must contain only digits.')
                if len(aadhar_cleaned) != 12:
                    raise ValueError('Aadhar number must be exactly 12 digits.')

            # Update user details
            fields_to_update = {
                'dob': request.POST.get('dob'),
                'blood_group': request.POST.get('blood_group'),
                'hire_date': request.POST.get('hire_date'),
                'gender': request.POST.get('gender'),
                'panno': request.POST.get('panno'),
                'job_description': request.POST.get('job_description'),
                'employment_status': request.POST.get('employment_status'),
                'emergency_contact_address': request.POST.get('emergency_contact_address'),
                'emergency_contact_primary': request.POST.get('emergency_contact_primary'),
                'emergency_contact_name': request.POST.get('emergency_contact_name'),
                'start_date': request.POST.get('start_date'),
                'work_location': request.POST.get('work_location'),
                'contact_number_primary': contact_number,
                'personal_email': request.POST.get('personal_email'),
                'aadharno': aadhar_number
            }

            # Remove None values to prevent overwriting with None
            fields_to_update = {k: v for k, v in fields_to_update.items() if v is not None}

            # Update the user_detail object
            for field, value in fields_to_update.items():
                setattr(user_detail, field, value)

            # Log the state before saving
            print("User Detail before save:", user_detail.__dict__)
            
            # Save the changes
            user_detail.save()
            
            # Log the state after saving
            print("User Detail after save:", user_detail.__dict__)

            messages.success(request, 'User details updated successfully.')
            return redirect('aps_hr:hr_dashboard')

        except ValueError as e:
            print(f"Validation Error for user {user_id}:", str(e))
            messages.error(request, str(e))
            return render(request, 'components/hr/hr_user_detail.html', {
                'user_detail': user_detail,
                'blood_group_choices': UserDetails._meta.get_field('blood_group').choices,
                'gender_choices': UserDetails._meta.get_field('gender').choices,
            })
        except Exception as e:
            print(f"Unexpected error for user {user_id}:", str(e))
            messages.error(request, f'Error updating user details: {str(e)}')
            return render(request, 'components/hr/hr_user_detail.html', {
                'user_detail': user_detail,
                'blood_group_choices': UserDetails._meta.get_field('blood_group').choices,
                'gender_choices': UserDetails._meta.get_field('gender').choices,
            })

    return render(request, 'components/hr/hr_user_detail.html', {
        'user_detail': user_detail,
        'blood_group_choices': UserDetails._meta.get_field('blood_group').choices,
        'gender_choices': UserDetails._meta.get_field('gender').choices,
    })


@login_required
@user_passes_test(is_manager)
def manager_employee_profile(request):
    """Manager Dashboard to view team members"""
    manager_group = request.user.groups.first()
    team_members = UserDetails.objects.filter(group=manager_group).exclude(user=request.user)
    
    return render(request, 'components/manager/manager_dashboard.html', {
        'team_members': team_members,
        'role': 'Manager',
        'user_detail': request.user.userdetails,
    })

@login_required
@user_passes_test(is_manager)
def manager_user_detail(request, user_id):
    """Manager view to see (but not edit) user details"""
    user_detail = get_object_or_404(UserDetails, id=user_id)
    
    return render(request, 'components/manager/manager_user_detail.html', {
        'user_detail': user_detail,
        'role': 'Manager'
    })

# Employee Views
# aps/views.py

@login_required
@user_passes_test(is_employee)
def employee_profile(request):
    """Employee Profile to view their own details"""
    try:
        user_detail = UserDetails.objects.get(user=request.user)
    except UserDetails.DoesNotExist:
        messages.error(request, 'Profile not found.')
        return redirect('home')
    
    return render(request, 'components/employee/employee_profile.html', {
        'user_detail': user_detail,
        'role': 'Employee'
    })

@login_required
def user_profile(request, user_id):
    """View to display user profile accessible to all logged-in users"""
    user_detail = get_object_or_404(UserDetails, user__id=user_id)
    
    return render(request, 'basic/user_profile.html', {
        'user_detail': user_detail,
    })

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
def change_password(request):
    if request.method == 'POST':
        # Logic for password change
        messages.success(request, "Password changed successfully.")
        return redirect('it_support_home')
    return render(request, 'components/employee/change_password.html')
# Attendance View

''' ---------------------------------------- TIMESHEET AREA ---------------------------------------- '''



@login_required
@user_passes_test(is_employee)  # Only allow employees to access this view
def timesheet_view(request):
    if request.method == "POST":
        try:
            # Get the submitted data from the form
            week_start_date = request.POST.get('week_start_date')
            project_names = request.POST.getlist('project_name[]')
            task_names = request.POST.getlist('task_name[]')
            hours = request.POST.getlist('hours[]')

            # Validate that project names, task names, and hours lists are all the same length
            if len(project_names) != len(task_names) or len(task_names) != len(hours):
                messages.error(request, "Project name, task name, and hours should have the same number of entries.")
                return redirect('aps:timesheet')

            # Create the Timesheet objects and save them to the database
            for project_name, task_name, hour in zip(project_names, task_names, hours):
                timesheet = Timesheet(
                    user=request.user,
                    week_start_date=week_start_date,
                    project_name=project_name,
                    task_name=task_name,
                    hours=float(hour)
                )
                timesheet.save()

            # Display success message
            messages.success(request, "Timesheet submitted successfully!")
            return redirect('aps:timesheet')

        except Exception as e:
            # If an error occurs, show an error message
            messages.error(request, f"An error occurred: {e}")
            return redirect('aps:timesheet')

    else:
        # If it's a GET request, show the current timesheet history
        today = timezone.now().date()

        # Fetch the timesheet history for the logged-in employee, ordered by week start date
        timesheet_history = Timesheet.objects.filter(user=request.user).order_by('-week_start_date')

        # Render the timesheet page with the data
        return render(request, 'components/employee/timesheet.html', {'today': today, 'timesheet_history': timesheet_history})

@login_required
@user_passes_test(is_manager)  # Only allow managers to access this view
def manager_view_timesheets(request):
    # Check if the logged-in user is a Manager, otherwise redirect
    if not request.user.groups.filter(name='Manager').exists():
        messages.error(request, "You do not have permission to view this page.")
        return redirect('aps:dashboard')

    # Fetch all timesheets for managers to review, ordered by week start date (descending)
    timesheets = Timesheet.objects.all().order_by('-week_start_date')

    # Calculate summary metrics:
    total_hours = sum(ts.hours for ts in timesheets)  # Sum of all hours worked
    active_projects = len(set(ts.project_name for ts in timesheets))  # Count of unique projects
    completion_rate = 85  # Placeholder - implement actual calculation for completion rate

    # Context data passed to the template
    context = {
        'timesheets': timesheets,
        'total_hours': total_hours,
        'active_projects': active_projects,
        'completion_rate': completion_rate,
    }

    # Render the timesheets to the manager's view template
    return render(request, 'components/manager/view_timesheets.html', context)

''' ---------------------------------------- LEAVE AREA ---------------------------------------- '''
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.http import Http404
from .models import Leave
from django.shortcuts import render, redirect
from django.contrib import messages
from .models import Leave
from django.contrib.auth.decorators import login_required, user_passes_test
from datetime import datetime

from django.shortcuts import render, redirect
from django.contrib import messages
from .models import Leave
from django.contrib.auth.decorators import login_required, user_passes_test
from datetime import datetime

@login_required
@user_passes_test(is_employee)
def leave_view(request):
    """Handle multiple leave functionalities on one page."""
    leave_balance = Leave.get_leave_balance(request.user)

    # Fetch leave requests for the current user
    leave_requests = Leave.objects.filter(user=request.user)

    # Handle leave request submission (creating a new leave request)
    if request.method == 'POST' and 'request_leave' in request.POST:
        leave_type = request.POST.get('leave_type')
        start_date = request.POST.get('start_date')
        end_date = request.POST.get('end_date')
        reason = request.POST.get('reason')

        # Print form data to check if it’s correctly received
        print(f"Request Leave - Leave Type: {leave_type}, Start Date: {start_date}, End Date: {end_date}, Reason: {reason}")

        try:
            start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
            end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
        except ValueError:
            messages.error(request, "Invalid date format. Please use YYYY-MM-DD.")
            return redirect('aps_employee:leave_view')

        if start_date > end_date:
            messages.error(request, "Start date cannot be after the end date.")
            return redirect('aps_employee:leave_view')

        leave_days = (end_date - start_date).days + 1
        leave_balance = Leave.get_leave_balance(request.user)

        if leave_balance['available_leave'] < leave_days:
            messages.error(request, "Insufficient leave balance.")
            return redirect('aps_employee:leave_view')

        # Create a new leave request
        Leave.objects.create(
            user=request.user,
            leave_type=leave_type,
            start_date=start_date,
            end_date=end_date,
            leave_days=leave_days,
            reason=reason,
            status='Pending',
        )
        print(f"Leave request for {leave_type} from {start_date} to {end_date} created.")
        messages.success(request, f"Leave request for {leave_type} from {start_date} to {end_date} has been submitted.")
        return redirect('aps_employee:leave_view')

    # Handle leave request updates (edit or delete)
    if request.method == 'POST' and 'edit_leave' in request.POST:
        leave_id = request.POST.get('leave_id')
        leave = Leave.objects.get(id=leave_id)
        if leave.user == request.user:
            print(f"Editing Leave Request - ID: {leave_id}")
            print(f"Form Data: start_date={request.POST.get('start_date')}, end_date={request.POST.get('end_date')}, reason={request.POST.get('reason')}")

            # Check if 'start_date' is present and not empty
            start_date = request.POST.get('start_date')
            if not start_date:
                messages.error(request, "Start date is required.")
                return redirect('aps_employee:leave_view')

            leave.start_date = start_date
            leave.end_date = request.POST.get('end_date')
            leave.reason = request.POST.get('reason')
            leave.status = request.POST.get('status', leave.status)
            leave.save()
            print(f"Leave request {leave_id} updated.")
            messages.success(request, "Leave request updated.")
            return redirect('aps_employee:leave_view')


    if request.method == 'POST' and 'delete_leave' in request.POST:
        leave_id = request.POST.get('leave_id')
        leave = Leave.objects.get(id=leave_id)
        if leave.user == request.user:
            print(f"Deleting Leave Request - ID: {leave_id}")
            leave.delete()
            print(f"Leave request {leave_id} deleted.")
            messages.success(request, "Leave request deleted.")
            return redirect('aps_employee:leave_view')

    # Render the page with the leave balance and the leave requests for the user
    print(f"Leave balance: {leave_balance}, Leave requests: {leave_requests}")
    return render(request, 'components/employee/leave.html', {
        'leave_balance': leave_balance,
        'leave_requests': leave_requests,  # Pass leave_requests to the template
    })

@login_required
@user_passes_test(is_hr)
def view_leave_requests_hr(request):
    """HR views all leave requests."""
    leave_requests = Leave.objects.all()
    return render(request, 'components/hr/view_leave_requests.html', {'leave_requests': leave_requests})


@login_required
@user_passes_test(is_hr)
def manage_leave_request_hr(request, leave_id, action):
    """HR approves or rejects leave requests."""
    leave_request = get_object_or_404(Leave, id=leave_id)

    if request.method == 'POST':
        if action == 'approve':
            leave_request.status = 'Approved'
            leave_request.approver = request.user
            leave_request.save()
            messages.success(request, f"Leave for {leave_request.user.username} approved.")
        elif action == 'reject':
            leave_request.status = 'Rejected'
            leave_request.approver = request.user
            leave_request.save()
            messages.warning(request, f"Leave for {leave_request.user.username} rejected.")
        return redirect('aps_hr:view_leave_requests_hr')

    return render(request, 'components/hr/manage_leave.html', {
        'leave_request': leave_request,
        'action': action.capitalize()
    })

@login_required
@user_passes_test(is_manager)
def view_leave_requests_manager(request):
    """HR views all leave requests."""
    leave_requests = Leave.objects.all()
    return render(request, 'components/manager/view_leave_requests.html', {'leave_requests': leave_requests})


@login_required
@user_passes_test(is_manager)
def manage_leave_request_manager(request, leave_id, action):
    """HR approves or rejects leave requests."""
    leave_request = get_object_or_404(Leave, id=leave_id)

    if request.method == 'POST':
        if action == 'approve':
            leave_request.status = 'Approved'
            leave_request.approver = request.user
            leave_request.save()
            messages.success(request, f"Leave for {leave_request.user.username} approved.")
        elif action == 'reject':
            leave_request.status = 'Rejected'
            leave_request.approver = request.user
            leave_request.save()
            messages.warning(request, f"Leave for {leave_request.user.username} rejected.")
        return redirect('aps_hr:view_leave_requests_hr')

    return render(request, 'components/manager/manage_leave.html', {
        'leave_request': leave_request,
        'action': action.capitalize()
    })

@login_required
@user_passes_test(is_admin)  # Admin can view all leave requests
def view_leave_requests_admin(request):
    """Admin view to see all leave requests"""
    leave_requests = Leave.objects.all()
    return render(request, 'components/admin/view_leave_requests.html', {'leave_requests': leave_requests})



@login_required
@user_passes_test(is_manager)
def view_leave_requests_manager(request):
    """View leave requests for a manager's team."""
    leave_requests = Leave.objects.filter(user__manager=request.user)  # Manager sees only their team's leave requests
    return render(request, 'components/manager/view_leave_requests.html', {'leave_requests': leave_requests})

# Admin, HR, Manager views to view leave requests remain as they are


''' ------------------------------------------- PROJECT AREA ------------------------------------------- '''

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.models import Group
from .models import Project, User, ProjectAssignment
from django.contrib.auth.decorators import login_required, user_passes_test

def get_users_from_group(group_name):
    """Fetch users dynamically from a given group."""
    try:
        group = Group.objects.get(name=group_name)
        return group.user_set.all()
    except Group.DoesNotExist:
        return User.objects.none()
from .models import Project, ProjectAssignment, ClientParticipation

@login_required
@user_passes_test(is_admin)
def project_view(request, action=None, project_id=None):
    """View to manage projects."""
    
    managers = get_users_from_group("Manager")
    employees = get_users_from_group("Employee")
    clients = get_users_from_group("Client")  # Fetch clients to manage client participation
    
    if action == "list":
        projects = Project.objects.all()
        return render(request, 'components/admin/project_view.html', {
            'projects': projects,
            'managers': managers,
            'employees': employees,
            'clients': clients
        })

    elif action == "detail" and project_id:
        project = get_object_or_404(Project, id=project_id)
        assignments = ProjectAssignment.objects.filter(project=project)
        client_participation = ClientParticipation.objects.filter(project=project)
        
        # Get the client names associated with the project
        clients_list = [client.client.username for client in client_participation]  # Assuming 'username' is the client's name
        
        context = {
            'project': project,
            'assignments': assignments,
            'clients': clients_list,  # Pass the list of client names to the template
            'project_id': project_id,
            'is_overdue': project.is_overdue() if hasattr(project, 'is_overdue') else False,
        }
        return render(request, 'components/admin/project_view.html', context)
    
    elif action == "create":
        if request.method == 'POST':
            try:
                name = request.POST.get('name')
                description = request.POST.get('description')
                due_date = request.POST.get('due_date')
                manager_id = request.POST.get('manager')
                client_ids = request.POST.getlist('clients')
                
                project = Project.objects.create(
                    name=name,
                    description=description,
                    deadline=due_date,
                    status='Not Started'
                )

                # Assign manager if selected
                if manager_id:
                    manager = User.objects.get(id=manager_id)
                    ProjectAssignment.objects.create(
                        project=project,
                        user=manager,
                        role_in_project='Manager'
                    )

                # Assign employees
                for employee_id in request.POST.getlist('employees'):
                    employee = User.objects.get(id=employee_id)
                    ProjectAssignment.objects.create(
                        project=project,
                        user=employee,
                        role_in_project='Employee'
                    )

                # Assign clients
                for client_id in client_ids:
                    client = User.objects.get(id=client_id)
                    ClientParticipation.objects.create(
                        project=project,
                        client=client,
                        feedback="",
                        approved=False
                    )

                messages.success(request, "Project created successfully!")
                return redirect('aps_admin:project_detail', project_id=project.id)

            except Exception as e:
                messages.error(request, f"Error creating project: {str(e)}")
                return redirect('aps_admin:project_view', action="list")

        return render(request, 'components/admin/project_view.html', {
            'managers': managers,
            'employees': employees,
            'clients': clients,
            'project_id': None
        })

    elif action == "update" and project_id:
        project = get_object_or_404(Project, id=project_id)
        
        if request.method == 'POST':
            try:
                project.name = request.POST.get('name', project.name)
                project.description = request.POST.get('description', project.description)
                project.status = request.POST.get('status', project.status)
                project.deadline = request.POST.get('deadline', project.deadline)
                project.save()

                # Reassign project members (manager, employees, clients)
                ProjectAssignment.objects.filter(project=project).delete()
                for employee_id in request.POST.getlist('employees'):
                    employee = User.objects.get(id=employee_id)
                    ProjectAssignment.objects.create(
                        project=project,
                        user=employee,
                        role_in_project='Employee'
                    )

                ClientParticipation.objects.filter(project=project).delete()
                for client_id in request.POST.getlist('clients'):
                    client = User.objects.get(id=client_id)
                    ClientParticipation.objects.create(
                        project=project,
                        client=client,
                        feedback="",
                        approved=False
                    )

                messages.success(request, "Project updated successfully!")
                return redirect('aps_admin:project_detail', project_id=project.id)

            except Exception as e:
                messages.error(request, f"Error updating project: {str(e)}")
                return redirect('aps_admin:project_view', action="detail", project_id=project.id)

        return render(request, 'components/admin/project_view.html', {
            'project': project,
            'managers': managers,
            'employees': employees,
            'clients': clients,
            'project_id': project_id
        })

    elif action == "delete" and project_id:
        project = get_object_or_404(Project, id=project_id)
        if request.method == 'POST':
            try:
                project.delete()
                messages.success(request, "Project deleted successfully!")
            except Exception as e:
                messages.error(request, f"Error deleting project: {str(e)}")
            return redirect('aps_admin:project_view', action="list")

        return render(request, 'components/admin/project_view.html', {
            'project': project,
            'project_id': project_id
        })

    elif action == "assign" and project_id:
        project = get_object_or_404(Project, id=project_id)

        if request.method == 'POST':
            try:
                # Assign employees to the project
                employee_ids = request.POST.getlist('employees')
                for employee_id in employee_ids:
                    employee = User.objects.get(id=employee_id)
                    ProjectAssignment.objects.create(
                        project=project,
                        user=employee,
                        role_in_project='Employee'
                    )

                # Assign clients to the project
                client_ids = request.POST.getlist('clients')
                for client_id in client_ids:
                    client = User.objects.get(id=client_id)
                    ClientParticipation.objects.create(
                        project=project,
                        client=client,
                        feedback="",
                        approved=False
                    )

                messages.success(request, "Users assigned successfully!")
                return redirect('aps_admin:project_detail', project_id=project.id)

            except Exception as e:
                messages.error(request, f"Error assigning users: {str(e)}")
                return redirect('aps_admin:project_detail', project_id=project.id)

        return render(request, 'components/admin/project_assign.html', {
            'project': project,
            'employees': employees,
            'clients': clients,
            'project_id': project_id
        })

    return redirect('aps_admin:project_list', action="list")

# @login_required
# @user_passes_test(is_admin)
# def project_view(request, action=None, project_id=None):
#     """View to manage projects."""
    
#     managers = get_users_from_group("Manager")
#     employees = get_users_from_group("Employee")
    
#     if action == "list":
#         projects = Project.objects.all()
#         return render(request, 'components/admin/project_view.html', {
#             'projects': projects,
#             'managers': managers,
#             'employees': employees
#         })

#     elif action == "detail" and project_id:
#         project = get_object_or_404(Project, id=project_id)
#         assignments = ProjectAssignment.objects.filter(project=project)
#         context = {
#             'project': project,
#             'assignments': assignments,
#             'project_id': project_id,  # Add this to ensure template knows we're in detail view
#             'is_overdue': project.is_overdue() if hasattr(project, 'is_overdue') else False,

#         }
#         return render(request, 'components/admin/project_view.html', context)
    
#     elif action == "create":
#         if request.method == 'POST':
#             try:
#                 # Extract form data
#                 name = request.POST.get('name')
#                 description = request.POST.get('description')
#                 due_date = request.POST.get('due_date')
#                 manager_id = request.POST.get('manager')
                
#                 # Create the project first
#                 project = Project.objects.create(
#                     name=name,
#                     description=description,
#                     deadline=due_date,
#                     status='Not Started'  # Set a default status
#                 )
                
#                 # Assign manager if selected
#                 if manager_id:
#                     try:
#                         manager = User.objects.get(id=manager_id)
#                         ProjectAssignment.objects.create(
#                             project=project,
#                             user=manager,
#                             role_in_project='Manager'
#                         )
#                     except User.DoesNotExist:
#                         messages.warning(request, "Selected manager not found.")

#                 # Handle employee assignments
#                 employees = request.POST.getlist('employees')  # Changed from 'employee' to 'employees'
#                 for employee_id in employees:
#                     try:
#                         employee = User.objects.get(id=employee_id)
#                         ProjectAssignment.objects.create(
#                             project=project,
#                             user=employee,
#                             role_in_project='Employee'
#                         )
#                     except User.DoesNotExist:
#                         messages.warning(request, f"Employee with ID {employee_id} not found.")

#                 messages.success(request, "Project created successfully!")
#                 return redirect('aps_admin:project_detail', project_id=project.id)  # Correct redirect for project detail page
                
#             except Exception as e:
#                 messages.error(request, f"Error creating project: {str(e)}")
#                 return redirect('aps_admin:project_view', action="list")

#         # GET request - show the creation form
#         return render(request, 'components/admin/project_view.html', {
#             'managers': managers,
#             'employees': employees,
#             'project_id': None  # Ensure we show the creation form
#         })

#     elif action == "update" and project_id:
#         project = get_object_or_404(Project, id=project_id)
        
#         if request.method == 'POST':
#             try:
#                 project.name = request.POST.get('name', project.name)
#                 project.description = request.POST.get('description', project.description)
#                 project.status = request.POST.get('status', project.status)
#                 project.deadline = request.POST.get('deadline', project.deadline)
#                 project.save()

#                 # Update assignments
#                 ProjectAssignment.objects.filter(project=project).delete()
                
#                 # Recreate manager assignment
#                 manager_id = request.POST.get('manager')
#                 if manager_id:
#                     manager = User.objects.get(id=manager_id)
#                     ProjectAssignment.objects.create(
#                         project=project,
#                         user=manager,
#                         role_in_project='Manager'
#                     )

#                 # Recreate employee assignments
#                 employee_ids = request.POST.getlist('employees')
#                 for employee_id in employee_ids:
#                     employee = User.objects.get(id=employee_id)
#                     ProjectAssignment.objects.create(
#                         project=project,
#                         user=employee,
#                         role_in_project='Employee'
#                     )

#                 messages.success(request, "Project updated successfully!")
#                 return redirect('aps_admin:project_detail', project_id=project.id)
            
#             except Exception as e:
#                 messages.error(request, f"Error updating project: {str(e)}")
#                 return redirect('aps_admin:project_view', action="detail", project_id=project.id)

#         return render(request, 'components/admin/project_view.html', {
#             'project': project,
#             'managers': managers,
#             'employees': employees,
#             'project_id': project_id
#         })

#     elif action == "delete" and project_id:
#         project = get_object_or_404(Project, id=project_id)
#         if request.method == 'POST':
#             try:
#                 project.delete()
#                 messages.success(request, "Project deleted successfully!")
#             except Exception as e:
#                 messages.error(request, f"Error deleting project: {str(e)}")
#             return redirect('aps_admin:project_view', action="list")
        
#         return render(request, 'components/admin/project_view.html', {
#             'project': project,
#             'project_id': project_id
#         })

#     return redirect('aps_admin:project_list', action="list")

@login_required
@user_passes_test(is_manager)
def manager_project_view(request, action=None, project_id=None):
    """Manager view for managing projects."""
    
    # Get all managers and employees
    managers = User.objects.filter(groups__name='Manager')
    employees = User.objects.filter(groups__name='Employee')

    # Action to list all projects
    if action == "list":
        # Get the current manager's projects
        assignments = ProjectAssignment.objects.filter(user=request.user, role_in_project='Manager')
        projects = [assignment.project for assignment in assignments]
        
        return render(request, 'components/manager/project_view.html', {
            'projects': projects,
            'managers': managers,
            'employees': employees
        })


    # Action to view project details
    elif action == "detail" and project_id:
        project = get_object_or_404(Project, id=project_id)
        assignments = ProjectAssignment.objects.filter(project=project)
        context = {
            'project': project,
            'assignments': assignments,
        }
        return render(request, 'components/manager/project_view.html', context)

    # Action to create a new project
    elif action == "create":
        if request.method == 'POST':
            try:
                # Extract form data from request.POST
                name = request.POST.get('name')
                description = request.POST.get('description')
                due_date = request.POST.get('due_date')
                
                # Create the project first
                project = Project.objects.create(
                    name=name,
                    description=description,
                    deadline=due_date,
                    status='Not Started'  # Set a default status
                )
                
                # Assign the manager if selected
                manager_id = request.POST.get('manager')
                if manager_id:
                    try:
                        manager = User.objects.get(id=manager_id)
                        ProjectAssignment.objects.create(
                            project=project,
                            user=manager,
                            role_in_project='Manager'
                        )
                    except User.DoesNotExist:
                        messages.warning(request, "Selected manager not found.")
                
                # Handle employee assignments
                employee_ids = request.POST.getlist('employees')  # Get selected employees
                for employee_id in employee_ids:
                    try:
                        employee = User.objects.get(id=employee_id)
                        ProjectAssignment.objects.create(
                            project=project,
                            user=employee,
                            role_in_project='Employee'
                        )
                    except User.DoesNotExist:
                        messages.warning(request, f"Employee with ID {employee_id} not found.")

                messages.success(request, "Project created successfully!")
                return redirect('aps_manager:project_detail', project_id=project.id)
            
            except Exception as e:
                messages.error(request, f"Error creating project: {str(e)}")
                return redirect('aps_manager:project_list')

        # GET request - show the creation form
        return render(request, 'components/manager/project_view.html', {
            'managers': managers,
            'employees': employees,
        })

    # Action to update an existing project
    elif action == "update" and project_id:
        project = get_object_or_404(Project, id=project_id)

        if request.method == 'POST':
            try:
                # Update project fields from request.POST
                project.name = request.POST.get('name', project.name)
                project.description = request.POST.get('description', project.description)
                project.status = request.POST.get('status', project.status)
                project.deadline = request.POST.get('deadline', project.deadline)
                project.save()

                # Update assignments - first delete existing assignments
                ProjectAssignment.objects.filter(project=project).delete()
                
                # Recreate manager assignment
                manager_id = request.POST.get('manager')
                if manager_id:
                    try:
                        manager = User.objects.get(id=manager_id)
                        ProjectAssignment.objects.create(
                            project=project,
                            user=manager,
                            role_in_project='Manager'
                        )
                    except User.DoesNotExist:
                        messages.warning(request, "Manager not found.")
                
                # Recreate employee assignments
                employee_ids = request.POST.getlist('employees')  # Get list of selected employees
                for employee_id in employee_ids:
                    try:
                        employee = User.objects.get(id=employee_id)
                        ProjectAssignment.objects.create(
                            project=project,
                            user=employee,
                            role_in_project='Employee'
                        )
                    except User.DoesNotExist:
                        messages.warning(request, f"Employee with ID {employee_id} not found.")


                messages.success(request, "Project updated successfully!")
                return redirect('aps_manager:project_detail', project_id=project.id)

            except Exception as e:
                messages.error(request, f"Error updating project: {str(e)}")
                return redirect('aps_manager:project_detail', project_id=project.id)

        # GET request - show the update form
        return render(request, 'components/manager/project_view.html', {
            'project': project,
            'managers': managers,
            'employees': employees,
        })

    return redirect('aps_manager:project_list')

''' ------------------------------------------- ATTENDACE AREA ------------------------------------------- '''

# Views with optimized database queries
import calendar

@login_required
def employee_attendance_view(request):
    # Get the month and year from the request, fallback to the current month/year
    current_date = datetime.now()
    current_month = int(request.GET.get('month', current_date.month))
    current_year = int(request.GET.get('year', current_date.year))
    current_month_name = calendar.month_name[current_month]
    
    # Get the previous and next month data
    prev_month = current_month - 1 if current_month > 1 else 12
    next_month = current_month + 1 if current_month < 12 else 1
    prev_year = current_year if current_month > 1 else current_year - 1
    next_year = current_year if current_month < 12 else current_year + 1
    
    # Get the calendar for the current month
    cal = calendar.Calendar(firstweekday=6)  # Start week on Sunday
    days_in_month = cal.monthdayscalendar(current_year, current_month)
    
    # Fetch attendance and leave data
    user_attendance = Attendance.objects.filter(user=request.user, date__month=current_month, date__year=current_year)
    leaves = Leave.objects.filter(user=request.user, start_date__month=current_month, start_date__year=current_year)
    
    # Attendance statistics
    total_present = user_attendance.filter(status='Present').count()
    total_absent = user_attendance.filter(status='Absent').count()
    total_leave = user_attendance.filter(status='On Leave').count()
    total_wfh = user_attendance.filter(status='Work From Home').count()

    # Leave balance
    leave_balance = Leave.get_leave_balance(request.user)

    # Calculate Loss of Pay for the month
    total_lop_days = Leave.calculate_lop_per_month(request.user, current_month, current_year)

    # Prepare calendar data (mark leave days)
    calendar_data = []
    for week in days_in_month:
        week_data = []
        for day in week:
            if day == 0:
                week_data.append({'empty': True})
            else:
                date = datetime(current_year, current_month, day)
                leave_status = None
                leave_type = None

                # Check if the day is a leave day
                leave_on_day = leaves.filter(start_date__lte=date, end_date__gte=date, status='Approved').first()
                if leave_on_day:
                    leave_status = 'On Leave'
                    leave_type = leave_on_day.leave_type
                
                # Check attendance for the day
                attendance_on_day = user_attendance.filter(date=date).first()
                if attendance_on_day:
                    leave_status = attendance_on_day.status
                    clock_in = attendance_on_day.clock_in_time if attendance_on_day.clock_in_time else None
                    clock_out = attendance_on_day.clock_out_time if attendance_on_day.clock_out_time else None
                    total_hours = attendance_on_day.total_hours if attendance_on_day.total_hours else None
                else:
                    clock_in = clock_out = total_hours = None
                
                week_data.append({
                    'date': day,
                    'is_today': date.date() == current_date.date(),
                    'status': leave_status,
                    'leave_type': leave_type,
                    'clock_in': clock_in,
                    'clock_out': clock_out,
                    'total_hours': total_hours,
                    'empty': False
                })
        calendar_data.append(week_data)

    # Pagination setup for attendance history
    paginator = Paginator(user_attendance, 10)
    page = request.GET.get('page')
    try:
        records = paginator.get_page(page)
    except EmptyPage:
        records = paginator.page(paginator.num_pages)
    except PageNotAnInteger:
        records = paginator.page(1)

    return render(request, 'components/employee/calander.html', {
        'current_month': current_month_name,
        'current_year': current_year,
        'prev_month': prev_month,
        'next_month': next_month,
        'prev_year': prev_year,
        'next_year': next_year,
        'calendar_data': calendar_data,
        'total_present': total_present,
        'total_absent': total_absent,
        'total_leave': total_leave,
        'total_wfh': total_wfh,
        'leave_balance': leave_balance,
        'total_lop_days': total_lop_days,
        'records': records
    })

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

from django.shortcuts import render
from django.contrib.auth.decorators import login_required, user_passes_test
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from .models import Attendance

from django.http import HttpResponse
from django.template.loader import render_to_string
import csv
import openpyxl
from datetime import datetime, timedelta
@login_required
@user_passes_test(is_hr)
def hr_attendance_view(request):
    # Optimized query using select_related
    all_attendance = Attendance.objects.select_related('user').order_by('-date')

    # Filters
    username_filter = request.GET.get('username', '')
    status_filter = request.GET.get('status', '')
    date_filter = request.GET.get('date', '')
    date_range_start = request.GET.get('start_date', '')
    date_range_end = request.GET.get('end_date', '')

    if username_filter:
        all_attendance = all_attendance.filter(user__username__icontains=username_filter)
    if status_filter:
        all_attendance = all_attendance.filter(status=status_filter)
    if date_filter:
        try:
            date_obj = datetime.strptime(date_filter, '%Y-%m-%d').date()
            all_attendance = all_attendance.filter(date=date_obj)
        except ValueError:
            pass  # If the date format is incorrect, it will be ignored

    # Filtering by date range
    if date_range_start and date_range_end:
        try:
            start_date = datetime.strptime(date_range_start, '%Y-%m-%d').date()
            end_date = datetime.strptime(date_range_end, '%Y-%m-%d').date()
            all_attendance = all_attendance.filter(date__range=[start_date, end_date])
        except ValueError:
            pass  # Handle invalid date format

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
    lop_count = all_attendance.filter(status='Loss of Pay').count()  # Add Loss of Pay count

    # Optimized working hours calculation
    for record in all_records:
        if record.clock_in_time and record.clock_out_time:
            clock_in_datetime = datetime.combine(record.date, record.clock_in_time)
            clock_out_datetime = datetime.combine(record.date, record.clock_out_time)
            working_hours = clock_out_datetime - clock_in_datetime
            hours = working_hours.seconds // 3600
            minutes = (working_hours.seconds % 3600) // 60
            record.working_hours = f"{hours}h {minutes}m"
        else:
            record.working_hours = None

    return render(request, 'components/hr/hr_admin_attendance.html', {
        'summary': all_records,
        'username_filter': username_filter,
        'status_filter': status_filter,
        'date_filter': date_filter,
        'date_range_start': date_range_start,
        'date_range_end': date_range_end,
        'present_count': present_count,
        'absent_count': absent_count,
        'leave_count': leave_count,
        'lop_count': lop_count,  # Include Loss of Pay count in the template context
    })


def export_attendance_csv(queryset):
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="attendance.csv"'

    writer = csv.writer(response)
    writer.writerow(['Employee', 'Username', 'Status', 'Date', 'Working Hours'])

    records = queryset.values(
        'user__first_name', 'user__last_name', 'user__username', 'status', 'date', 'working_hours'
    )
    for record in records:
        writer.writerow([
            f"{record['user__first_name']} {record['user__last_name']}",
            record['user__username'],
            record['status'],
            record['date'].strftime('%Y-%m-%d'),
            record['working_hours'],
        ])
    return response


def export_attendance_excel(queryset):
    response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
    response['Content-Disposition'] = 'attachment; filename="attendance.xlsx"'

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Attendance"
    ws.append(['Employee', 'Username', 'Status', 'Date', 'Working Hours'])

    records = queryset.values(
        'user__first_name', 'user__last_name', 'user__username', 'status', 'date', 'working_hours'
    )
    for record in records:
        ws.append([
            f"{record['user__first_name']} {record['user__last_name']}",
            record['user__username'],
            record['status'],
            record['date'].strftime('%Y-%m-%d'),
            record['working_hours'],
        ])
    wb.save(response)
    return response


@login_required
@user_passes_test(is_admin)
def admin_attendance_view(request):
    # Similar improvements for admin view
    username_filter = request.GET.get('username', '')
    status_filter = request.GET.get('status', '')
    date_filter = request.GET.get('date', '')
    date_range_start = request.GET.get('start_date', '')
    date_range_end = request.GET.get('end_date', '')

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
    if date_range_start and date_range_end:
        try:
            start_date = datetime.strptime(date_range_start, '%Y-%m-%d').date()
            end_date = datetime.strptime(date_range_end, '%Y-%m-%d').date()
            attendance_summary = attendance_summary.filter(date__range=[start_date, end_date])
        except ValueError:
            pass  # Handle invalid date format

    attendance_summary = attendance_summary.values(
        'user', 'user__first_name', 'user__last_name', 'user__username', 'status', 'date', 'working_hours'
    ).order_by('-date')

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
        'date_filter': date_filter,
        'date_range_start': date_range_start,
        'date_range_end': date_range_end,
    })

'''------------------------------------------------ SUPPORT  AREA------------------------------------------------'''


@login_required
@user_passes_test(is_employee)
def employee_support(request):
    """Employee's Support Home with the ability to create a ticket."""
    
    print("Accessed employee_support view")

    if request.method == 'POST':
        print("POST request received")
        issue_type = request.POST.get('issue_type')
        description = request.POST.get('description')
        subject = request.POST.get('subject', 'No subject')  # Added subject to the form

        print(f"Issue Type: {issue_type}")
        print(f"Description: {description}")
        print(f"Subject: {subject}")

        # Validate the required fields
        if not issue_type or not description:
            print("Validation failed: Issue Type or Description is missing")
            messages.error(request, "Issue Type and Description are required.")
            return redirect('aps_employee:employee_support')

        # Assign ticket based on issue type (HR issues go to HR, others to Admin)
        assigned_to = 'Admin' if issue_type != 'HR Related Issue' else 'HR'
        print(f"Assigned to: {assigned_to}")

        try:
            # Create a new support ticket
            Support.objects.create(
                user=request.user,
                issue_type=issue_type,
                description=description,
                subject=subject,  # Store the subject entered by the employee
                status='Open',
                assigned_to=assigned_to
            )
            print("Ticket created successfully")
            messages.success(request, "Your ticket has been created successfully.")
        except Exception as e:
            print(f"Error occurred: {str(e)}")
            messages.error(request, f"An error occurred: {str(e)}")
            return redirect('aps_employee:employee_support')

    # Fetch tickets raised by the logged-in employee
    tickets = Support.objects.filter(user=request.user).order_by('-created_at')
    print(f"Fetched {tickets.count()} tickets for user {request.user}")

    # Fetch issue type choices dynamically
    issue_type_choices = [choice[0] for choice in Support.ISSUE_TYPE_CHOICES]
    print(f"Issue type choices: {issue_type_choices}")

    return render(request, 'components/employee/support.html', {
        'tickets': tickets,
        'issue_type_choices': issue_type_choices
    })

from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
from .models import Support

def is_admin(user):
    return user.groups.filter(name='Admin').exists()

@login_required
@user_passes_test(is_admin)
def admin_support(request, ticket_id=None):
    try:
        if ticket_id:
            ticket = get_object_or_404(Support, ticket_id=ticket_id)
            
            if request.method == 'POST':
                status = request.POST.get('status')
                if status in dict(Support.STATUS_CHOICES):
                    ticket.status = status
                    ticket.save()
                    messages.success(request, f"Ticket {ticket.ticket_id} updated to {status}.")
                    return redirect('aps_admin:admin_support')
                else:
                    messages.error(request, "Invalid status selected.")
            
            return render(request, 'components/admin/support_admin.html', {
                'ticket': ticket,
                'is_admin': True
            })
        
        # List view
        tickets = Support.objects.all()
        context = {
            'tickets': tickets,
            'open_tickets': tickets.filter(status='Open').count(),
            'in_progress_tickets': tickets.filter(status='In Progress').count(),
            'resolved_tickets': tickets.filter(status='Resolved').count(),
            'is_admin': True
        }
        return render(request, 'components/admin/support_admin.html', context)
        
    except Exception as e:
        messages.error(request, "An error occurred while managing tickets.")
        return redirect('aps_admin:admin_support')
    


def is_hr(user):
    return user.groups.filter(name='HR').exists()
def is_hr(user):
    return user.groups.filter(name='HR').exists()

@login_required
@user_passes_test(is_hr)
def hr_support(request, ticket_id=None):
    """HR view to manage tickets and see ticket details."""
    try:
        if ticket_id:
            # Handle single ticket view and updates
            ticket = get_object_or_404(Support, ticket_id=ticket_id)
            
            if request.method == 'POST':
                status = request.POST.get('status')
                if status in dict(Support.STATUS_CHOICES):
                    # Only allow HR to update tickets assigned to HR
                    if ticket.assigned_to == 'HR':
                        ticket.status = status
                        ticket.save()
                        messages.success(request, f"Ticket {ticket.ticket_id} updated to {status}.")
                        return redirect('aps_hr:hr_support')
                    else:
                        messages.error(request, "You can only update HR-assigned tickets.")
                else:
                    messages.error(request, "Invalid status selected.")
            
            return render(request, 'components/hr/support_hr.html', {
                'ticket': ticket,
                'is_hr': True,
                'can_update': ticket.assigned_to == 'HR'  # Only show update form for HR tickets
            })
        
        # List view - Show only HR-relevant tickets
        tickets = Support.objects.filter(
            Q(assigned_to='HR') |  # Tickets assigned to HR
            Q(issue_type='HR Related Issue')  # HR-related issues
        ).order_by('-created_at')
        
        context = {
            'tickets': tickets,
            'open_tickets': tickets.filter(status='Open').count(),
            'in_progress_tickets': tickets.filter(status='In Progress').count(),
            'resolved_tickets': tickets.filter(status='Resolved').count(),
            'is_hr': True,
            'total_tickets': tickets.count()
        }
        
        return render(request, 'components/hr/support_hr.html', context)
        
    except Exception as e:
        print(f"HR Support Error: {str(e)}")  # For debugging
        messages.error(request, "An error occurred while managing tickets.")
        return redirect('aps_hr:hr_support')
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



