from django.shortcuts import render
from django.contrib.auth.models import User, Group
from .models import (UserSession, Attendance, SystemError, 
                    Support, FailedLoginAttempt, PasswordChange, 
                    RoleAssignmentAudit, FeatureUsage, SystemUsage, 
                    Timesheet,GlobalUpdate,
                    Message, Chat,UserDetails,ProjectUpdate, Project, ProjectAssignment)
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

'''------------------------------ TRACKING ------------------------'''


@login_required
@csrf_exempt
def update_last_activity(request):
    """
    View to handle activity updates from the client.
    Updates the user's last activity timestamp and tracks idle time.
    """
    if request.method == 'POST':
        try:
            # Get current user session
            user_session = UserSession.objects.filter(
                user=request.user,
                session_key=request.session.session_key,
                logout_time__isnull=True
            ).last()

            if not user_session:
                return JsonResponse({
                    'status': 'error',
                    'message': 'No active session found'
                }, status=404)

            current_time = timezone.now()
            
            # Calculate time since last activity
            time_since_last_activity = current_time - user_session.last_activity
            
            # If more than 1 minute has passed, count it as idle time
            if time_since_last_activity > timedelta(minutes=1):
                user_session.idle_time += time_since_last_activity
            
            # Update last activity
            user_session.last_activity = current_time
            
            # If working_hours is not set and we have both login and last activity
            if user_session.working_hours is None and user_session.login_time:
                user_session.working_hours = current_time - user_session.login_time

            # Save only the modified fields
            user_session.save(update_fields=['last_activity', 'idle_time', 'working_hours'])

            return JsonResponse({
                'status': 'success',
                'last_activity': current_time.isoformat(),
                'idle_time': str(user_session.idle_time),
                'working_hours': str(user_session.working_hours) if user_session.working_hours else None
            })

        except Exception as e:
            return JsonResponse({
                'status': 'error',
                'message': str(e)
            }, status=400)

    return JsonResponse({
        'status': 'error',
        'message': 'Invalid request method'
    }, status=405)

@login_required
def end_session(request):
    """
    View to handle session end/logout.
    Calculates final working hours and idle time.
    """
    try:
        user_session = UserSession.objects.filter(
            user=request.user,
            session_key=request.session.session_key,
            logout_time__isnull=True
        ).last()

        if user_session:
            current_time = timezone.now()
            
            # Calculate final idle time
            time_since_last_activity = current_time - user_session.last_activity
            if time_since_last_activity > timedelta(minutes=1):
                user_session.idle_time += time_since_last_activity
            
            # Set logout time
            user_session.logout_time = current_time
            
            # Calculate total working hours
            total_duration = current_time - user_session.login_time
            user_session.working_hours = total_duration - user_session.idle_time
            
            user_session.save()

            return JsonResponse({
                'status': 'success',
                'message': 'Session ended successfully',
                'working_hours': str(user_session.working_hours),
                'idle_time': str(user_session.idle_time)
            })

        return JsonResponse({
            'status': 'error',
            'message': 'No active session found'
        }, status=404)

    except Exception as e:
        return JsonResponse({
            'status': 'error',
            'message': str(e)
        }, status=400)

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

from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from .models import Break
from django.utils.timezone import now
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required

@login_required
def check_active_break(request):
    """
    Check if the authenticated user has an active break.
    """
    print(f"Checking active break for user: {request.user.username}")
    active_break = Break.objects.filter(user=request.user, end_time__isnull=True).first()
    if active_break and active_break.is_active:
        print(f"Active break found: {active_break}")
        return JsonResponse({
            'status': 'success',
            'break_id': active_break.id,
            'break_type': active_break.break_type,
            'start_time': active_break.start_time,
            'is_active': active_break.is_active
        })
    else:
        print("No active break found")
        return JsonResponse({'status': 'error', 'message': 'No active break found'})

def take_break(request):
    if request.method == 'POST':
        break_type = request.POST.get('break_type')

        # Ensure valid break type
        if not break_type or break_type not in dict(Break.BREAK_TYPES).keys():
            messages.error(request, "Invalid break type.")
            return redirect('dashboard')

        # Create new break
        new_break = Break(user=request.user, break_type=break_type)
        try:
            # Run validation to check for active breaks and limits
            new_break.clean()  # This will run all validations from the `clean` method
            new_break.save()
            messages.success(request, f"Started {break_type}")
        except ValidationError as e:
            messages.error(request, str(e))
        
        return redirect('dashboard')

    # For GET requests, show available breaks
    available_breaks = Break.get_available_breaks(request.user)
    context = {
        'available_breaks': available_breaks,
        'break_durations': Break.BREAK_DURATIONS
    }
    return render(request, 'breaks/take_break.html', context)

from django.urls import reverse

@login_required
def end_break(request, break_id):
    if request.method == 'POST':
        try:
            print(f"Ending break with ID: {break_id} for user: {request.user.username}")
            active_break = get_object_or_404(Break, id=break_id, user=request.user, end_time__isnull=True)
            
            max_duration = Break.BREAK_DURATIONS.get(active_break.break_type, timedelta(minutes=15))
            # Use timezone.now() for consistent timezone-aware datetime
            elapsed_time = timezone.now() - active_break.start_time
            
            if elapsed_time > max_duration and not request.POST.get('reason'):
                return JsonResponse({
                    'status': 'error',
                    'message': 'Please provide a reason for the extended break.'
                })
            
            reason = request.POST.get('reason', '')
            # Use timezone.now() when setting end_time
            active_break.end_time = timezone.now()
            active_break.reason_for_extension = reason
            active_break.save()
            print(f"Break ended with reason: {reason}")
            
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({'status': 'success'})
            
            return redirect(f"{reverse('dashboard')}?success=Break ended successfully")
            
        except Exception as e:
            return redirect(f"{reverse('dashboard')}?error={str(e)}")
    
    return redirect(f"{reverse('dashboard')}?error=Invalid request method")

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
from django.utils import timezone

@login_required
def dashboard_view(request):
    user = request.user

    # Check if the user has the HR role
    is_hr = user.groups.filter(name='HR').exists()
    is_manager = user.groups.filter(name='Manager').exists()

    # Variables for attendance stats and active projects
    present_employees = absent_employees = active_projects = None

    # Get today's date using timezone-aware datetime
    today = timezone.now().date()

    # Get date range from request (default to today if not provided)
    start_date_str = request.GET.get('start_date', today)
    end_date_str = request.GET.get('end_date', today)

    # Convert string date inputs to date format
    try:
        start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date() if isinstance(start_date_str, str) else today
        end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date() if isinstance(end_date_str, str) else today
    except ValueError:
        return JsonResponse({'status': 'error', 'message': 'Invalid date format. Use YYYY-MM-DD.'})

    # Ensure the end date is inclusive
    end_date += timedelta(days=1)

    # Check if the user has an active break
    active_break = Break.objects.filter(user=user, end_time__isnull=True).first()
    break_data = None
    if active_break and active_break.is_active:
        # Get break duration in minutes
        break_duration = Break.BREAK_DURATIONS.get(active_break.break_type, timedelta(minutes=15))
        
        # Ensure both times are timezone-aware
        now = timezone.now()
        elapsed_time = now - active_break.start_time
        remaining_time = max(timedelta(0), break_duration - elapsed_time)
        
        break_data = {
            'break_id': active_break.id,
            'break_type': active_break.break_type,
            'start_time': active_break.start_time,
            'active_break': active_break.is_active,
            'remaining_minutes': int(remaining_time.total_seconds() / 60),
            'remaining_seconds': int(remaining_time.total_seconds() % 60)
        }

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

    # Get project timelines for each project
    project_timelines = []
    for project in projects:
        timeline = project_timeline(request, project.id)  # Returns a dictionary with project info
        project_timelines.append(timeline['project']) 

    # Retrieve global updates
    updates = GlobalUpdate.objects.all().order_by('-created_at')

    # Retrieve project team updates
    project_team_updates = ProjectUpdate.objects.all()

    # Check if we are editing an update
    update = None
    if 'update_id' in request.GET:
        update = GlobalUpdate.objects.filter(id=request.GET['update_id']).first()

    # Context for the dashboard view
    context = {
        'attendance': get_attendance_stats(user),
        'projects': projects,
        'project_timelines': project_timelines,
        'updates': updates,
        'is_hr': is_hr,
        'is_manager': is_manager,
        'projectTeamUpdates': project_team_updates,
        'update': update,
        'present_employees': present_employees,
        'absent_employees': absent_employees,
        'active_projects': active_projects,
        'start_date': start_date,
        'end_date': end_date - timedelta(days=1),
        'show_employee_directory': is_hr,
        'break_data': break_data,
        'break_types': dict(Break.BREAK_TYPES),
        'break_durations': {k: int(v.total_seconds() / 60) for k, v in Break.BREAK_DURATIONS.items()}
    }

    return render(request, 'dashboard.html', context)


def project_timeline(request, project_id):
    project = Project.objects.get(id=project_id)
    current_date = timezone.now().date()
    
    # Calculate total project duration and remaining time
    total_duration = project.deadline - project.start_date
    remaining_duration = project.deadline - current_date
    
    # Check if remaining time is within the last 25% of the total duration
    is_deadline_close = remaining_duration <= total_duration * 0.25

    
    return {
        'project': {
            'name': project.name,
            'start_date': project.start_date,
            'deadline': project.deadline,  # No need to include 'deadline' twice
            'is_deadline_close': is_deadline_close,
        }
    }



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


''' ------------------------------------------------------- MANAGER TEAM PROJECT AREA --------------------------------------------------------- '''

@login_required
@user_passes_test(is_manager)
@transaction.atomic
def manager_create_project_update(request):
    """Manager creates an update for their project."""
    if request.method == 'POST':
        project_id = request.POST.get('project_id')
        title = request.POST.get('title')
        description = request.POST.get('description')
        status = request.POST.get('status', 'upcoming')
        scheduled_date_str = request.POST.get('scheduled_date')

        # Validate fields
        if not title or not description or not project_id:
            messages.error(request, "Title, description, and project are required.")
            return redirect('dashboard')

        try:
            # Fetch the project assigned to the manager
            project = get_object_or_404(Project, id=project_id)
            project_assignment = ProjectAssignment.objects.filter(project=project, user=request.user, is_active=True).first()
            if not project_assignment or project_assignment.role_in_project != 'Manager':
                messages.error(request, "You are not assigned as the manager for this project.")
                return redirect('dashboard')

            # Handle scheduled date
            scheduled_date = None
            if scheduled_date_str:
                scheduled_date = datetime.strptime(scheduled_date_str, '%Y-%m-%dT%H:%M')
                scheduled_date = timezone.make_aware(scheduled_date)

            # Create the project update
            new_update = ProjectUpdate.objects.create(
                project=project,
                created_by=request.user,
                title=title,
                description=description,
                status=status,
                scheduled_date=scheduled_date
            )

            messages.success(request, "Project update created successfully.")
            return redirect('dashboard')

        except Exception as e:
            messages.error(request, f"Error creating update: {str(e)}")
            return redirect('dashboard')

    return redirect('dashboard')

@login_required
@user_passes_test(is_manager)
@transaction.atomic
def manager_edit_project_update(request, update_id):
    """Manager edits an existing project update."""
    try:
        update = get_object_or_404(ProjectUpdate, id=update_id)
        if update.created_by != request.user:
            messages.error(request, "You do not have permission to edit this update.")
            return redirect('dashboard')

        if request.method == 'POST':
            title = request.POST.get('title')
            description = request.POST.get('description')
            status = request.POST.get('status', 'upcoming')
            scheduled_date_str = request.POST.get('scheduled_date')

            if not title or not description:
                return JsonResponse({'error': 'Title and description are required'}, status=400)

            scheduled_date = None
            if scheduled_date_str:
                try:
                    scheduled_date = datetime.strptime(scheduled_date_str, '%Y-%m-%dT%H:%M')
                    update.scheduled_date = timezone.make_aware(scheduled_date)
                except ValueError:
                    return JsonResponse({'error': 'Invalid date format'}, status=400)

            update.title = title
            update.description = description
            update.status = status
            update.save()

            messages.success(request, "Project update edited successfully.")
            return redirect('dashboard')  # Redirect to the dashboard after successful edit

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=405)

@login_required
@user_passes_test(is_manager)
@transaction.atomic
def manager_delete_project_update(request, update_id):
    """Manager deletes a project update."""
    try:
        update = get_object_or_404(ProjectUpdate, id=update_id)
        if update.created_by != request.user:
            messages.error(request, "You do not have permission to delete this update.")
            return redirect('dashboard')

        update.delete()
        messages.success(request, "Project update deleted successfully.")
        return redirect('dashboard')

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
                # Check if the timesheet for the same user, week, project, and task already exists
                existing_timesheet = Timesheet.objects.filter(
                    user=request.user,
                    week_start_date=week_start_date,
                    project__name=project_name,  # Changed to filter by project name
                    task_name=task_name
                ).first()

                if existing_timesheet:
                    existing_timesheet.hours += float(hour)  # Update hours if already exists
                    existing_timesheet.save()
                else:
                    # Fetch project using the name
                    project = Project.objects.get(name=project_name)
                    timesheet = Timesheet(
                        user=request.user,
                        week_start_date=week_start_date,
                        project=project,  # Set project using name
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
            return redirect('aps_employee:timesheet')

    else:
        # If it's a GET request, show the current timesheet history
        today = timezone.now().date()

        # Fetch the timesheet history for the logged-in employee, ordered by week start date
        timesheet_history = Timesheet.objects.filter(user=request.user).order_by('-week_start_date')

        # Fetch the list of projects the user is assigned to using the ProjectAssignment model
        assigned_projects = Project.objects.filter(projectassignment__user=request.user, projectassignment__is_active=True)

        # Render the timesheet page with the data
        return render(request, 'components/employee/timesheet.html', {
            'today': today,
            'timesheet_history': timesheet_history,
            'assigned_projects': assigned_projects,  # Pass the list of assigned projects
        })


from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.decorators import login_required, user_passes_test
from .models import Timesheet
from django.db.models import Sum, Count
from django.utils import timezone

from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.decorators import login_required, user_passes_test
from django.utils import timezone
from .models import Timesheet
from django.db.models import Sum
from datetime import timedelta
from django.http import JsonResponse

@login_required
@user_passes_test(is_manager)
def manager_view_timesheets(request):
    time_filter = request.GET.get('time-filter', '7')
    search_query = request.GET.get('search', '')
    filter_days = int(time_filter)

    # Base queryset with prefetching for optimization
    timesheets = Timesheet.objects.select_related('project', 'user').filter(
        week_start_date__gte=timezone.now() - timedelta(days=filter_days)
    )

    # Search filter
    if search_query:
        timesheets = timesheets.filter(
            Q(user__first_name__icontains=search_query) |
            Q(user__last_name__icontains=search_query) |
            Q(project__name__icontains=search_query) |
            Q(task_name__icontains=search_query)
        )

    # Ordering and pagination
    timesheets = timesheets.order_by('-week_start_date', 'user__first_name')
    paginator = Paginator(timesheets, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    timesheets = timesheets.annotate(
        user_total_hours=Sum('hours'),
        user_pending_count=Count('id', filter=Q(approval_status='Pending'))
    )

    # Statistics calculation
    total_hours = timesheets.aggregate(Sum('hours'))['hours__sum'] or 0
    active_projects = timesheets.values('project').distinct().count()
    completion_rate = calculate_completion_rate(timesheets)
    pending_approvals = timesheets.filter(approval_status='Pending').count()

    context = {
        'page_obj': page_obj,
        'total_hours': total_hours,
        'active_projects': active_projects,
        'completion_rate': completion_rate,
        'pending_approvals': pending_approvals,
        'time_filter': time_filter,
        'search_query': search_query,
    }

    return render(request, 'components/manager/view_timesheets.html', context)


@login_required
@user_passes_test(is_manager)
def bulk_update_timesheet(request):
    if request.method != 'POST':
        return JsonResponse({'success': False, 'message': 'Invalid request method'}, status=405)

    timesheet_ids = request.POST.getlist('selected_timesheets[]')
    action = request.POST.get('action')

    if not timesheet_ids:
        messages.error(request, 'No timesheets selected.')
        return redirect('aps_manager:view_timesheets')

    if action not in ['approve', 'reject']:
        messages.error(request, 'Invalid action.')
        return redirect('aps_manager:view_timesheets')

    status_map = {
        'approve': 'Approved',
        'reject': 'Rejected'
    }

    try:
        managed_projects = ProjectAssignment.objects.filter(
            user=request.user, role_in_project='Manager', is_active=True
        ).values_list('project', flat=True)

        # Restrict timesheets to manager's projects
        timesheets = Timesheet.objects.filter(
            id__in=timesheet_ids,
            project_id__in=managed_projects
        )

        if not timesheets.exists():
            messages.error(request, 'You are not authorized to update the selected timesheets.')
            return redirect('aps_manager:view_timesheets')

        # Update timesheets
        update_count = timesheets.update(
            approval_status=status_map[action],
            reviewed_at=timezone.now()
        )

        messages.success(
            request,
            f'Successfully {action}d {update_count} timesheet{"s" if update_count != 1 else ""}.'
        )
    except Exception as e:
        logger.error(f"Error processing timesheets: {e}")
        messages.error(request, 'An unexpected error occurred while processing timesheets.')

    return redirect('aps_manager:view_timesheets')


def calculate_completion_rate(timesheets):
    total_count = timesheets.count()
    if total_count == 0:
        return 0

    approved_count = timesheets.filter(approval_status='Approved').count()
    completion_rate = (approved_count / total_count) * 100
    return round(completion_rate, 2)
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
    print(f"Leave requests fetched: {leave_requests}")
    return render(request, 'components/manager/view_leave_requests.html', {'leave_requests': leave_requests})


@login_required
@user_passes_test(is_manager)
def manage_leave_request_manager(request, leave_id, action):
    """HR approves or rejects leave requests."""
    leave_request = get_object_or_404(Leave, id=leave_id)
    print(f"Managing leave request: {leave_request} for action: {action}")

    if request.method == 'POST':
        if action == 'approve':
            print(f"Approving leave request: {leave_request}")
            leave_request.status = 'Approved'
            leave_request.approver = request.user
            leave_request.save()
            messages.success(request, f"Leave for {leave_request.user.username} approved.")
        elif action == 'reject':
            print(f"Rejecting leave request: {leave_request}")
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


# View for managing a project (creating, editing, viewing)
@login_required
@user_passes_test(is_admin)  # You can adjust this if other roles should access this view
def project_view(request, project_id=None):
    """View for managing a project (creating, editing, viewing)."""
    
    if project_id:
        project = get_object_or_404(Project, id=project_id)
    else:
        project = None  # If no project_id is provided, it means we are creating a new project
    
    return render(request, 'components/admin/project/view_project.html', {'project': project})
# Admin can create new project
@login_required
@user_passes_test(is_admin)
def add_project(request):
    """View for adding a new project."""
    
    # Define the form directly in the view
    class ProjectForm(forms.ModelForm):
        class Meta:
            model = Project
            fields = ['name', 'description', 'deadline', 'status']

    if request.method == 'POST':
        form = ProjectForm(request.POST)
        if form.is_valid():
            project = form.save()
            return redirect('view_project', project_id=project.id)  # Redirect to the project details page
    else:
        form = ProjectForm()

    return render(request, 'components/admin/project/add_project.html', {'form': form})

# Admin or Manager can assign a manager to a project
@login_required
@user_passes_test(is_admin)
def assign_manager(request, project_id):
    """View for assigning a manager to a project."""
    project = get_object_or_404(Project, id=project_id)
    if request.method == 'POST':
        manager_username = request.POST.get('manager')
        manager = get_object_or_404(User, username=manager_username)
        assignment = ProjectAssignment.objects.create(project=project, user=manager, role_in_project='Manager')
        return redirect('view_project', project_id=project.id)

    # Get a list of users that can be assigned as manager
    available_managers = User.objects.filter(groups__name="Manager")
    return render(request, 'components/admin/project/assign_manager.html', {'project': project, 'available_managers': available_managers})

# Admin or Manager can assign employees to a project
@login_required
@require_http_methods(["POST"])
def assign_employee(request, project_id):
    """View for assigning an employee to a project."""
    project = get_object_or_404(Project, id=project_id)
    
    # Define the form directly in the view
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

    # Get a list of users that can be assigned as employees
    available_employees = User.objects.filter(groups__name="Employee")
    return render(request, 'components/admin/project/assign_employee.html', {'project': project, 'form': form, 'available_employees': available_employees})

# Employees log their worked hours on a project
@login_required
@user_passes_test(lambda user: user.groups.filter(name__in=['Admin', 'Manager', 'Employee']).exists())
def log_hours(request, project_assignment_id):
    """View for employees to log hours worked on a project."""
    assignment = get_object_or_404(ProjectAssignment, id=project_assignment_id)
    if request.method == 'POST':
        hours_worked = request.POST.get('hours_worked')
        assignment.hours_worked += float(hours_worked)
        assignment.save()
        return redirect('view_project', project_id=assignment.project.id)

    return JsonResponse({'status': 'success', 'message': 'Employee role updated successfully'})

# Admin and Manager can view project details including overdue status
@login_required
@user_passes_test(lambda user: user.groups.filter(name__in=['Admin', 'Manager']).exists())
def view_project(request, project_id):
    """View for viewing the project details, including overdue status."""
    project = get_object_or_404(Project, id=project_id)
    overdue = project.is_overdue()  # Check if the project is overdue
    assignments = ProjectAssignment.objects.filter(project=project)
    return render(request, 'components/admin/project/view_project.html', {'project': project, 'overdue': overdue, 'assignments': assignments})

# Admin and Manager can view all projects and their status
@login_required
@user_passes_test(lambda user: user.groups.filter(name__in=['Admin', 'Manager']).exists())
def all_projects(request):
    """View to list all projects with their status."""
    projects = Project.objects.all()
    return render(request, 'components/admin/project/all_projects.html', {'projects': projects})



''' ------------------------------------------- ATTENDACE AREA ------------------------------------------- '''

# Views with optimized database queries
@login_required
def employee_attendance_view(request):
    current_date = datetime.now()
    current_month = int(request.GET.get('month', current_date.month))
    current_year = int(request.GET.get('year', current_date.year))
    current_month_name = calendar.month_name[current_month]
    
    prev_month = current_month - 1 if current_month > 1 else 12
    next_month = current_month + 1 if current_month < 12 else 1
    prev_year = current_year if current_month > 1 else current_year - 1
    next_year = current_year if current_month < 12 else current_year + 1
    
    cal = calendar.Calendar(firstweekday=6)  
    days_in_month = cal.monthdayscalendar(current_year, current_month)
    
    user_attendance = Attendance.objects.filter(user=request.user, date__month=current_month, date__year=current_year)
    leaves = Leave.objects.filter(user=request.user, start_date__month=current_month, start_date__year=current_year)
    
    total_present = user_attendance.filter(status='Present').count()
    total_absent = user_attendance.filter(status='Absent').count()
    total_leave = user_attendance.filter(status='On Leave').count()
    total_wfh = user_attendance.filter(status='Work From Home').count()

    leave_balance = Leave.get_leave_balance(request.user)
    total_lop_days = Leave.calculate_lop_per_month(request.user, current_month, current_year)

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
                clock_in = clock_out = total_hours = None

                leave_on_day = leaves.filter(start_date__lte=date, end_date__gte=date, status='Approved').first()
                if leave_on_day:
                    leave_status = 'On Leave'
                    leave_type = leave_on_day.leave_type
                
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

from django.shortcuts import render
from django.contrib.auth.decorators import login_required, user_passes_test
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from .models import Attendance

from django.http import HttpResponse
from django.template.loader import render_to_string
import csv
import openpyxl
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

# Admin Attendance View
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
