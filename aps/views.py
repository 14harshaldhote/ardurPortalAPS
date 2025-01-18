from django.shortcuts import render
from django.contrib.auth.models import User, Group
from .models import (UserSession, Attendance, SystemError, 
                    Support, FailedLoginAttempt, PasswordChange, 
                    RoleAssignmentAudit, FeatureUsage, SystemUsage, 
                    Timesheet,GlobalUpdate,
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
from django.utils.dateparse import parse_date
from django.views.decorators.csrf import csrf_exempt
import sys
import traceback
from django.db import transaction
from django.shortcuts import render
from django.contrib.auth.decorators import login_required, user_passes_test
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from .models import Attendance

from django.http import HttpResponse
from django.template.loader import render_to_string
import csv
import openpyxl
from datetime import datetime, timedelta




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


@login_required
def dashboard_view(request):
    from datetime import datetime, timedelta
    from django.utils.timezone import now

    user = request.user

    # Check if the user has the HR role
    is_hr = user.groups.filter(name='HR').exists()

    # Variables for attendance stats and active projects
    present_employees = absent_employees = active_projects = None

    # Get today's date
    today = now().date()

    # Get date range from request (default to today if not provided)
    start_date = request.GET.get('start_date', today)
    end_date = request.GET.get('end_date', today)

    # Parse date range if provided as strings
    if isinstance(start_date, str):
        start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
    if isinstance(end_date, str):
        end_date = datetime.strptime(end_date, '%Y-%m-%d').date()

    # Ensure the end date is inclusive
    end_date += timedelta(days=1)

    if is_hr:
        # Get attendance stats
        present_employees = Attendance.objects.filter(
            status='Present', date__range=[start_date, end_date]
        ).count()
        absent_employees = Attendance.objects.filter(
            status='Absent', date__range=[start_date, end_date]
        ).count()

        # Get active projects
        active_projects = Project.objects.filter(status='Active').count()

    # Retrieve assignments and projects for non-HR users
    assignments = ProjectAssignment.objects.filter(user=user)
    projects = [assignment.project for assignment in assignments]

    # Retrieve global updates
    updates = GlobalUpdate.objects.all().order_by('-created_at')

    # Check if we are editing an update
    update = None
    if 'update_id' in request.GET:
        update = GlobalUpdate.objects.filter(id=request.GET['update_id']).first()

    # Context for the dashboard view
    context = {
        'attendance': get_attendance_stats(user),  # Function to fetch overall attendance stats for the user
        'projects': projects,
        'updates': updates,
        'is_hr': is_hr,
        'update': update,
        'present_employees': present_employees,
        'absent_employees': absent_employees,
        'active_projects': active_projects,  # Pass active projects for HR
        'start_date': start_date,
        'end_date': end_date - timedelta(days=1),  # Exclude added day
        'show_employee_directory': is_hr,
    }

    return render(request, 'dashboard.html', context)


from django.utils.timezone import now, timezone



@user_passes_test(is_hr)
@login_required
def employee_directory(request):
    # Check if the user has the HR role
    if not request.user.groups.filter(name='HR').exists():
        return JsonResponse({'error': 'Permission denied'}, status=403)

    # Fetch all employee details
    employees = UserDetails.objects.all().values(
        'id', 'user__username', 'user__first_name', 'user__last_name', 'contact_number_primary', 'personal_email'
    )
    
    # Convert queryset to list of dictionaries
    employee_data = list(employees)
    
    # Return the data as JSON
    return JsonResponse({'employees': employee_data})

# Create global update view
@login_required
@transaction.atomic
def hr_create_update(request):
    if not request.user.groups.filter(name='HR').exists():
        messages.error(request, "You do not have permission to manage global updates.")
        return redirect('dashboard')

    if request.method == 'POST':
        title = request.POST.get('title')
        description = request.POST.get('description')
        status = request.POST.get('status', 'upcoming')
        scheduled_date_str = request.POST.get('scheduled_date')

        if not title or not description:
            messages.error(request, "Title and description are required.")
            return redirect('dashboard')

        try:
            scheduled_date = None
            if scheduled_date_str:
                scheduled_date = datetime.strptime(scheduled_date_str, '%Y-%m-%dT%H:%M')
                scheduled_date = timezone.make_aware(scheduled_date)  # Make timezone-aware

            new_update = GlobalUpdate.objects.create(
                title=title,
                description=description,
                status=status,
                scheduled_date=scheduled_date,
                managed_by=request.user,
            )

            messages.success(request, "Global update created successfully.")
            return redirect('dashboard')
        except Exception as e:
            messages.error(request, "Error creating update. Please try again.")
            return redirect('dashboard')

    return redirect('dashboard')

# Get update data API for editing
@login_required
def get_update_data(request, update_id):
    """API endpoint to fetch update data for editing"""
    if not request.user.groups.filter(name='HR').exists():
        return JsonResponse({'error': 'Permission denied'}, status=403)

    try:
        update = get_object_or_404(GlobalUpdate, id=update_id)
        data = {
            'title': update.title,
            'description': update.description,
            'status': update.status,
            'scheduled_date': update.scheduled_date.isoformat() if update.scheduled_date else '',
        }
        return JsonResponse(data)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)

# Edit global update view
@login_required
@transaction.atomic
def hr_edit_update(request, update_id):
    """View to handle update editing"""
    update = get_object_or_404(GlobalUpdate, id=update_id)
    
    # Check permissions
    if not request.user.groups.filter(name='HR').exists():
        messages.error(request, "You do not have permission to edit this update.")
        return JsonResponse({'error': 'Permission denied'}, status=403)
    
    if request.method == 'POST':
        try:
            # Get form data
            title = request.POST.get('title')
            description = request.POST.get('description')
            status = request.POST.get('status')
            scheduled_date_str = request.POST.get('scheduled_date')
            
            # Validate required fields
            if not title or not description:
                return JsonResponse({'error': 'Title and description are required'}, status=400)
            
            # Update fields
            update.title = title
            update.description = description
            update.status = status
            
            if scheduled_date_str:
                try:
                    scheduled_date = datetime.strptime(scheduled_date_str, '%Y-%m-%dT%H:%M')
                    update.scheduled_date = timezone.make_aware(scheduled_date)
                except ValueError:
                    return JsonResponse({'error': 'Invalid date format'}, status=400)
            else:
                update.scheduled_date = None
            
            update.save()
            messages.success(request, "Global update edited successfully.")
            return redirect('dashboard')  # Redirect to the dashboard after successful deletion
            
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    
    return JsonResponse({'error': 'Invalid request method'}, status=405)

# Delete global update view
@login_required
@transaction.atomic
def hr_delete_update(request, update_id):
    """View to handle update deletion"""
    if not request.user.groups.filter(name='HR').exists():
        return JsonResponse({'error': 'Permission denied'}, status=403)

    try:
        update = get_object_or_404(GlobalUpdate, id=update_id)
        update.delete()
        messages.success(request, "Global update deleted successfully.")
        return redirect('dashboard')  # Redirect to the dashboard after successful deletion
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
    
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

        # Print form data to check if it's correctly received
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
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.contrib import messages
from django.utils import timezone
from django.db.models import Q, Sum
from django.core.exceptions import ValidationError
from .models import Project, ProjectAssignment, ClientParticipation, User
from django.views.decorators.http import require_http_methods
from django.db import transaction
from django.urls import reverse
import json
import logging
from django.contrib.auth.models import Group
from datetime import datetime

# Set up logging
logger = logging.getLogger(__name__)

class ProjectError(Exception):
    """Custom exception for project-related errors"""
    pass

def parse_request_data(request):
    """Helper method to parse request data consistently"""
    try:
        if request.content_type == 'application/json':
            return json.loads(request.body)
        return request.POST
    except json.JSONDecodeError as e:
        logger.error(f"JSON parsing error: {str(e)}")
        raise ProjectError("Invalid JSON data provided")

def validate_project_dates(start_date, deadline):
    """Validate project dates"""
    if start_date > deadline:
        raise ValidationError("Start date cannot be after deadline")
    if deadline < timezone.now().date():
        raise ValidationError("Deadline cannot be in the past")

def handle_assignment_changes(project, assignment, action='assign', role='Employee'):
    """Helper method to handle employee assignment changes"""
    try:
        if action == 'assign':
            if assignment:
                # Reactivate if previously deactivated
                assignment.is_active = True
                assignment.end_date = None
                assignment.role_in_project = role
                assignment.save()
                return False  # Not created, but updated
            return True  # New assignment created
        else:  # remove
            assignment.deactivate()
            return True
    except Exception as e:
        logger.error(f"Assignment change error: {str(e)}")
        raise ProjectError(f"Error {action}ing employee")

def get_users_from_group(group_name):
    """Fetch users dynamically from a given group."""
    try:
        group = Group.objects.get(name=group_name)
        return group.user_set.all()
    except Group.DoesNotExist:
        return User.objects.none()


# Assuming logger is set up
logger = logging.getLogger(__name__)

@login_required
def project_dashboard(request):
    try:
        today = date.today()

        # Get all active projects with related data
        projects = Project.objects.prefetch_related(
            'users', 
            'clients', 
            'projectassignment_set__user',
            'client_participations'
        ).all()

        # Print the project objects (you can adjust this as needed)
        print("Projects data:")
        for project in projects:
            print(f"Project ID: {project.id}, Project Name: {project.name}, Deadline: {project.deadline}")

            # Print the users related to the project (through projectassignment_set)
            print(f"Assigned Users for Project {project.name}:")
            for assignment in project.projectassignment_set.all():
                user = assignment.user
                print(f"  - User: {user.get_full_name()} (ID: {user.id}, Role: {assignment.get_role_in_project_display()})")

        for project in projects:
            # Calculate project duration and remaining days
            project_duration = (project.deadline - project.start_date).days
            remaining_days = (project.deadline - today).days
            
            remaining_percentage = max((remaining_days / project_duration) * 100, 0) if project_duration > 0 else 0

            # Set deadline status
            project.is_deadline_close = 0 <= remaining_percentage <= 10

            # Fetch active and removed assignments
            project.active_assignments = project.projectassignment_set.filter(is_active=True)
            project.removed_assignments = project.projectassignment_set.filter(is_active=False)

            # Print active assignments
            print(f"Project: {project.name} (Active Assignments)")
            for assignment in project.active_assignments:
                assignment.user.full_name = assignment.user.get_full_name()
                print(f"  - {assignment.user.full_name} (ID: {assignment.user.id}, Role: {assignment.get_role_in_project_display()})")
            
            # Print removed assignments
            print(f"Project: {project.name} (Removed Assignments)")
            for assignment in project.removed_assignments:
                assignment.user.full_name = assignment.user.get_full_name()
                print(f"  - {assignment.user.full_name} (ID: {assignment.user.id}, Ended: {assignment.end_date})")

        # Fetch users by group
        employees = get_users_from_group('Employee')
        managers = get_users_from_group('Manager')
        clients = get_users_from_group('Client')
                
        # Fetch role choices
        role_choices = dict(ProjectAssignment._meta.get_field('role_in_project').choices)

        # Context for rendering the template
        context = {
            'projects': projects,
            'employees': employees,
            'clients': clients,
            'managers': managers,
            'project_statuses': dict(Project._meta.get_field('status').choices),
            'role_choices': role_choices,
            'active_assignments': project.active_assignments,  # Ensure this is passed
            'removed_assignments': project.removed_assignments,  # Ensure this is passed

        }

        return render(request, 'components/admin/project_view.html', context)

    except Exception as e:
        # Capture exception details
        exc_type, exc_value, exc_tb = sys.exc_info()
        error_details = traceback.format_exception(exc_type, exc_value, exc_tb)

        # Log error and display error message
        logger.error(f"Dashboard error: {str(e)}")
        messages.error(request, "Error loading dashboard")

        # Provide detailed error information in the context for debugging
        context = {
            'error': str(e),
            'error_details': error_details,
        }
        return render(request, 'error.html', context)


@login_required
@require_http_methods(["POST"])
def project_create(request):
    """Handle project creation"""
    try:
        data = request.POST
        start_date_str = data.get('start_date')
        deadline_str = data.get('deadline')
        
        try:
            start_date = parse_date(start_date_str)
            deadline = parse_date(deadline_str)
            if not start_date or not deadline:
                raise ValidationError("Invalid date format. Expected 'YYYY-MM-DD'.")
        except ValueError:
            raise ValidationError("Invalid date format. Expected 'YYYY-MM-DD'.")

        validate_project_dates(start_date, deadline)
        
        with transaction.atomic():
            project = Project.objects.create(
                name=data.get('name'),
                description=data.get('description'),
                start_date=start_date,
                deadline=deadline,
                status='Pending'
            )
            
            client_ids = data.getlist('clients') if hasattr(data, 'getlist') else []
            if client_ids:
                project.clients.set(client_ids)
                for client_id in client_ids:
                    ClientParticipation.objects.create(project=project, client_id=client_id)
            
            manager_id = data.get('manager')
            if manager_id:
                ProjectAssignment.objects.create(project=project, user_id=manager_id, role_in_project='Manager')
            
            employee_ids = data.getlist('employees') if hasattr(data, 'getlist') else []
            for emp_id in employee_ids:
                ProjectAssignment.objects.create(project=project, user_id=emp_id, role_in_project='Employee')

        logger.info(f"Project created successfully: {project.name}")
        return redirect(reverse('aps_admin:project_dashboard'))
        
    except ValidationError as e:
        logger.warning(f"Validation error in project creation: {str(e)}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=400)
    except Exception as e:
        logger.error(f"Error creating project: {str(e)}")
        return JsonResponse({'status': 'error', 'message': 'Internal server error'}, status=500)
    
def update_project_status(project):
    """Automatically update project status based on dates"""
    today = datetime.now().date()

    # If the project is completed (Deadline passed)
    if project.deadline and today > project.deadline and project.status != 'Completed':
        project.status = 'Completed'
    
    # If the project is in progress (Start date has passed but deadline hasn't passed)
    elif project.start_date and today >= project.start_date and (not project.deadline or today <= project.deadline):
        project.status = 'In Progress'
    
    # If the project is on hold or any other condition you may define
    elif project.status != 'On Hold':  # Example condition
        project.status = 'On Hold'
    
    project.save()
  
@login_required
@user_passes_test(is_admin)
@require_http_methods(["POST"])
def project_update(request, project_id):
    """Handle project updates"""
    print(f"Updating project with ID: {project_id}")  # Debug line

    try:
        project = get_object_or_404(Project, id=project_id)
        data = parse_request_data(request)
        
        # Validate status from the form (if provided)
        new_status = data.get('status')
        if new_status and new_status not in ['Completed', 'In Progress', 'Pending', 'On Hold']:
            raise ValidationError("Invalid project status")
        
        # Update project status explicitly
        if new_status:
            project.status = new_status
        
        # Convert deadline to a date object if provided and ensure it's a string
        # Handle deadline field
        if 'deadline' in data and data['deadline']:
            deadline = data.get('deadline')
            try:
                # Convert deadline to a date object only if it's not empty
                if deadline:
                    deadline = datetime.strptime(deadline, '%Y-%m-%d').date()

                    # Validate that deadline is not in the past and that it is later than start_date
                    if deadline < datetime.now().date():
                        raise ValidationError("Deadline cannot be in the past.")
                    if project.start_date and deadline < project.start_date:
                        raise ValidationError("Deadline cannot be earlier than the start date.")

                    project.deadline = deadline
            except ValueError:
                raise ValidationError("Invalid date format for deadline. Please use YYYY-MM-DD.")

            project.deadline = deadline
        
        with transaction.atomic():
            # Update project basic info
            project.name = data.get('name', project.name)
            project.description = data.get('description', project.description)
            
            project.save()
        
        return redirect(reverse('aps_admin:project_dashboard'))  # Adjust the name of the URL pattern if needed

    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


def parse_request_data(request):
    """Helper function to parse data from the request"""
    return {
        'name': request.POST.get('name'),
        'description': request.POST.get('description'),
        'start_date': request.POST.get('start_date'),
        'deadline': request.POST.get('deadline'),
        'status': request.POST.get('status'),
    }


@login_required
@user_passes_test(is_admin)
@require_http_methods(["POST"])
def project_delete(request, project_id):
    """Handle project deletion"""
    try:
        project = get_object_or_404(Project, id=project_id)

        with transaction.atomic():
            # Soft delete all assignments
            ProjectAssignment.objects.filter(project=project).update(
                is_active=False,
                end_date=timezone.now().date()
            )

            # Soft delete all client participations
            ClientParticipation.objects.filter(project=project).update(is_active=False)

            # Delete the project
            project.delete()

        logger.info(f"Project deleted successfully: {project.name}")
        return redirect(reverse('aps_admin:project_dashboard'))  # This is fine after defining the URL

    except Exception as e:
        logger.error(f"Error deleting project: {str(e)}")
        return JsonResponse({'status': 'error', 'message': 'Internal server error'}, status=500)


@csrf_exempt
@login_required
@require_http_methods(["POST"])
def assign_employee(request, project_id):
    """Handle employee assignment to project dynamically, including deactivation"""
    try:
        with transaction.atomic():
            print(f"Transaction started for project_id: {project_id}")
            project = get_object_or_404(Project, id=project_id)
            print(f"Project found: {project.name} (ID: {project.id})")

            user_id = request.POST.get('user_id')
            role = request.POST.get('role', 'Employee')
            action = request.POST.get('action', 'assign')  # Action for remove or assign
            print(f"Received data - user_id: {user_id}, role: {role}, action: {action}")

            if not user_id:
                return JsonResponse({
                    'status': 'error',
                    'message': 'User ID is required'
                }, status=400)

            # Ensure role is valid
            role_choices = dict(ProjectAssignment._meta.get_field('role_in_project').choices)
            if role not in role_choices:
                return JsonResponse({
                    'status': 'error',
                    'message': f'Invalid role. Available roles are {", ".join(role_choices.keys())}'
                }, status=400)

            user = get_object_or_404(User, id=user_id)
            print(f"User found: {user.username} (ID: {user.id})")

            if action == 'remove':
                assignment = project.projectassignment_set.filter(user=user, is_active=True).first()

                if not assignment:
                    return JsonResponse({
                        'status': 'error',
                        'message': f'No active assignment found for employee {user.username} in this project'
                    }, status=404)

                # Soft delete by marking inactive
                assignment.is_active = False
                assignment.end_date = timezone.now().date()
                assignment.save()
                return JsonResponse({
                    'status': 'success',
                    'message': f'Employee {user.username} removed from the project'
                })

            # Check if the employee has been previously removed (soft deleted)
            assignment = project.projectassignment_set.filter(user=user, is_active=False).first()

            if assignment:
                # Reactivate the assignment if it was previously removed
                assignment.is_active = True
                assignment.role_in_project = role
                assignment.end_date = None  # Clear end_date if reactivating
                assignment.save()
                return JsonResponse({
                    'status': 'success',
                    'message': f'Employee {user.username} reactivated in the project'
                })
            else:
                # Handle assigning or updating an employee's role if not previously removed
                assignment, created = ProjectAssignment.objects.get_or_create(
                    project=project,
                    user=user
                )

                assignment.role_in_project = role
                assignment.is_active = True
                assignment.save()

                return JsonResponse({
                    'status': 'success',
                    'message': f'Employee {user.username} assigned to the project with role {role}'
                })

    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)

@csrf_exempt
@login_required
@require_http_methods(["POST"])
def change_role(request, project_id):
    """Handle changing the role of an assigned employee"""
    try:
        with transaction.atomic():
            project = get_object_or_404(Project, id=project_id)
            user_id = request.POST.get('user_id')
            new_role = request.POST.get('role', 'Employee')

            if not user_id:
                return JsonResponse({'status': 'error', 'message': 'User ID is required'}, status=400)

            # Ensure role is valid
            role_choices = dict(ProjectAssignment._meta.get_field('role_in_project').choices)
            if new_role not in role_choices:
                return JsonResponse({
                    'status': 'error',
                    'message': f'Invalid role. Available roles are {", ".join(role_choices.keys())}'
                }, status=400)

            user = get_object_or_404(User, id=user_id)
            assignment = project.projectassignment_set.filter(user=user, is_active=True).first()

            if not assignment:
                return JsonResponse({'status': 'error', 'message': 'No active assignment found for this user'}, status=404)

            assignment.role_in_project = new_role
            assignment.save()

            return JsonResponse({'status': 'success', 'message': 'Employee role updated successfully'})

    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)

@csrf_exempt
@login_required
@require_http_methods(["POST"])
def reactivate_employee(request, project_id):
    """Handle reactivating a previously removed employee"""
    try:
        with transaction.atomic():
            project = get_object_or_404(Project, id=project_id)
            user_id = request.POST.get('user_id')

            if not user_id:
                return JsonResponse({'status': 'error', 'message': 'User ID is required'}, status=400)

            user = get_object_or_404(User, id=user_id)
            assignment = project.projectassignment_set.filter(user=user, is_active=False).first()

            if not assignment:
                return JsonResponse({'status': 'error', 'message': 'No removed assignment found for this user'}, status=404)

            assignment.is_active = True
            assignment.end_date = None  # Clear end date
            assignment.save()

            return JsonResponse({'status': 'success', 'message': 'Employee reactivated successfully'})

    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


@login_required
@require_http_methods(["POST"])
def update_hours(request, project_id):
    """Handle updating worked hours for an assignment"""
    try:
        project = get_object_or_404(Project, id=project_id)
        data = parse_request_data(request)
        
        user_id = data.get('user_id')
        hours = data.get('hours')
        
        if not user_id or hours is None:
            raise ValidationError("User ID and hours are required")
        
        try:
            hours = float(hours)
            if hours < 0:
                raise ValidationError("Hours cannot be negative")
        except ValueError:
            raise ValidationError("Invalid hours value")
        
        assignment = get_object_or_404(
            ProjectAssignment,
            project=project,
            user_id=user_id,
            is_active=True
        )
        
        assignment.update_hours(hours)
        
        logger.info(f"Hours updated successfully: {hours} hours for {user_id} in {project.name}")
        return JsonResponse({
            'status': 'success',
            'message': 'Hours updated successfully',
            'total_hours': assignment.get_total_hours()
        })
        
    except ValidationError as e:
        logger.warning(f"Validation error in hours update: {str(e)}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=400)
    except Exception as e:
        logger.error(f"Error updating hours: {str(e)}")
        return JsonResponse({'status': 'error', 'message': 'Internal server error'}, status=500)

# @login_required
# @user_passes_test(is_admin)
# def project_view(request, action=None, project_id=None):
#     """View to manage projects."""

#     managers = get_users_from_group("Manager")
#     employees = get_users_from_group("Employee")
#     clients = get_users_from_group("Client")

#     if action == "list":
#         projects = Project.objects.all()
#         return render(request, 'components/admin/project_view.html', {
#             'projects': projects,
#             'managers': managers,
#             'employees': employees,
#             'clients': clients,
#         })

#     elif action == "detail" and project_id:
#         project = get_object_or_404(Project, id=project_id)
#         assignments = ProjectAssignment.objects.filter(project=project)
#         client_participation = ClientParticipation.objects.filter(project=project)
#         clients_list = [client.client.username for client in client_participation]

#         return render(request, 'components/admin/project_view.html', {
#             'project': project,
#             'assignments': assignments,
#             'clients': clients_list,
#             'project_id': project_id,
#             'is_overdue': project.is_overdue() if hasattr(project, 'is_overdue') else False,
#         })

#     elif action == "create":
#         if request.method == 'POST':
#             try:
#                 project = create_project(request)
#                 messages.success(request, "Project created successfully!")
#                 return redirect('aps_admin:project_detail', project_id=project.id)
#             except Exception as e:
#                 messages.error(request, f"Error creating project: {str(e)}")
#                 return redirect('aps_admin:project_view', action="list")

#         return render(request, 'components/admin/project_view.html', {
#             'managers': managers,
#             'employees': employees,
#             'clients': clients,
#             'project_id': None,
#         })

#     elif action == "update" and project_id:
#         project = get_object_or_404(Project, id=project_id)
#         status_choices = Project._meta.get_field('status').choices


#         if request.method == 'POST':
#             try:
#                 update_project(request, project)
#                 messages.success(request, "Project updated successfully!")
#                 return redirect('aps_admin:project_detail', project_id=project.id)
#             except Exception as e:
#                 messages.error(request, f"Error updating project: {str(e)}")
#                 return redirect('aps_admin:project_view', action="detail", project_id=project.id)

#         assignments = ProjectAssignment.objects.filter(project=project)
#         current_managers = [assignment.user.id for assignment in assignments.filter(role_in_project='Manager')]

#         return render(request, 'components/admin/project_view.html', {
#             'project': project,
#             'managers': managers,
#             'current_managers': current_managers,
#             'employees': employees,
#             'clients': clients,
#             'project_id': project_id,
#             'action': 'update',
#             'status_choices': status_choices,  # Pass status choices

#         })

#     elif action == "delete" and project_id:
#         project = get_object_or_404(Project, id=project_id)
#         if request.method == 'POST':
#             try:
#                 project.delete()
#                 messages.success(request, "Project deleted successfully!")
#                 print("Project deletion successful")  # Debugging line
#             except Exception as e:
#                 messages.error(request, f"Error deleting project: {str(e)}")
#             return redirect('aps_admin:projects_list')
#         return render(request, 'components/admin/project_view.html', {
#             'project': project,
#             'project_id': project_id,
#         })

#     elif action == "assign" and project_id:
#         project = get_object_or_404(Project, id=project_id)
#         role_choices = ProjectAssignment._meta.get_field('role_in_project').choices


#         if request.method == 'POST':
#             try:
#                 assign_users_to_project(request, project)
#                 messages.success(request, "Users assigned successfully!")
#                 return redirect('aps_admin:project_detail', project_id=project.id)
#             except Exception as e:
#                 messages.error(request, f"Error assigning users: {str(e)}")
#                 return redirect('aps_admin:project_detail', project_id=project.id)

#         manager = project.projectassignment_set.filter(role_in_project='Manager').first()

#         return render(request, 'components/admin/project_view.html', {
#             'project': project,
#             'employees': employees,
#             'clients': clients,
#             'assignments': ProjectAssignment.objects.filter(project=project),
#             'manager': manager,
#             'project_id': project_id,
#             'action': 'assign',  # Add this line to ensure 'assign' action is passed
#             'role_choices': role_choices,  # Pass role choices

#         })


#     return redirect('aps_admin:project_list', action="list")


def create_project(request):
    """Helper function to create a project."""
    name = request.POST.get('name')
    description = request.POST.get('description')
    start_date = request.POST.get('start_date')
    due_date = request.POST.get('due_date')
    client_ids = request.POST.getlist('clients')  # Ensure client_ids are being captured here
    print("Client IDs:", client_ids)  # Add this line for debugging
    
    project = Project.objects.create(
        name=name,
        description=description,
        start_date=start_date,
        deadline=due_date,
        status='Not Started'
    )
    
    assign_users_to_project(request, project, client_ids)  # Pass client_ids to the assign function
    return project


def update_project(request, project):
    """Helper function to update a project."""
    project.name = request.POST.get('name', project.name)
    project.description = request.POST.get('description', project.description)
    project.status = request.POST.get('status', project.status)
    project.start_date = request.POST.get('start_date', project.start_date)
    project.deadline = request.POST.get('deadline', project.deadline)
    project.save()

    # Reassign clients based on selected client_ids (Handle soft deletes if necessary)
    client_ids = request.POST.getlist('clients')
    # Clear current clients and reassign based on new client_ids
    project.clients.clear()  
    for client_id in client_ids:
        client = User.objects.get(id=client_id)
        project.clients.add(client)

    return project


def assign_users_to_project(request, project, client_ids=None):
    """Helper function to assign users to a project."""
    # Assign manager
    manager_id = request.POST.get('manager')
    if manager_id:
        manager = User.objects.get(id=manager_id)
        ProjectAssignment.objects.update_or_create(
            project=project,
            user=manager,
            defaults={'role_in_project': 'Manager', 'hours_worked': 0.0}
        )
    
    # Assign employees
    employee_ids = request.POST.getlist('employees')
    for employee_id in employee_ids:
        employee = User.objects.get(id=employee_id)
        ProjectAssignment.objects.get_or_create(
            project=project,
            user=employee,
            defaults={'role_in_project': 'Employee', 'hours_worked': 0.0}
        )
    
    # Assign clients if client_ids are passed
    if client_ids:
        for client_id in client_ids:  # Iterate through the passed client_ids
            client = User.objects.get(id=client_id)
            ClientParticipation.objects.get_or_create(
                project=project,
                client=client,
                defaults={'feedback': '', 'approved': False}
            )

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



