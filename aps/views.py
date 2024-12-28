from django.shortcuts import render
from django.contrib.auth.models import User, Group
from .models import UserSession, ITSupportTicket, Attendance, SystemError, UserComplaint, FailedLoginAttempt, PasswordChange, RoleAssignmentAudit, FeatureUsage, SystemUsage
from django.db.models import Q
from datetime import datetime, timedelta
from django.utils import timezone
from datetime import datetime
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required, user_passes_test
from .helpers import is_user_in_group

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



@login_required
def dashboard_view(request):
    try:
        return render(request, 'dashboard.html')

    except Exception as e:
        # Handle errors by passing the error message to the template
        return render(request, 'dashboard.html', {'error': f'An error occurred: {str(e)}'})

''' --------------------------------------------------------- ADMIN AREA --------------------------------------------------------- '''
# Helper function to check if the user belongs to the Admin group
def is_admin(user):
    """Check if the user belongs to the Admin group using Group model."""
    admin_group_id = 1  # Admin group ID from auth_group table
    return user.groups.filter(id=admin_group_id).exists()


@login_required  # Ensure the user is logged in
@user_passes_test(is_admin)  # Ensure the user is an admin
def report_view(request):
    nav_items = [
        {'id': 'featureusage', 'name': 'Feature Usage', 'icon': 'fas fa-chart-line'},
        {'id': 'projects', 'name': 'Projects', 'icon': 'fas fa-project-diagram'},
        {'id': 'systemerrors', 'name': 'System Errors', 'icon': 'fas fa-exclamation-triangle'},
        {'id': 'systemusage', 'name': 'System Usage', 'icon': 'fas fa-desktop'},
    ]
    return render(request, 'components/admin/report.html', {'nav_items': nav_items})


def feature_usage(request):
    return render(request, 'components/admin/reports/feature_usage.html')

def projects_report(request):
    return render(request, 'components/admin/reports/projects_report.html')

def system_errors(request):
    return render(request, 'components/admin/reports/system_errors.html')

def system_usage(request):
    return render(request, 'components/admin/reports/system_usage.html')


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


# View for Feature Usage Information
@login_required
@user_passes_test(is_admin)
def feature_usage_view(request):
    """View to display feature usage details."""
    try:
        feature_usages = FeatureUsage.objects.all().order_by('-usage_count')
        return render(request, 'components/admin/feature_usage.html', {'feature_usages': feature_usages})

    except Exception as e:
        messages.error(request, f"An error occurred while fetching feature usage data: {str(e)}")
        return redirect('dashboard')


# View for System Errors
@login_required
@user_passes_test(is_admin)
def system_error_view(request):
    """View to display system errors."""
    try:
        system_errors = SystemError.objects.all().order_by('-error_time')
        return render(request, 'components/admin/system_error.html', {'system_errors': system_errors})

    except Exception as e:
        messages.error(request, f"An error occurred while fetching system errors: {str(e)}")
        return redirect('dashboard')


# View for User Complaints
@login_required
@user_passes_test(is_admin)
def user_complaint_view(request):
    """View to display user complaints."""
    try:
        user_complaints = UserComplaint.objects.all().order_by('-complaint_date')
        return render(request, 'components/admin/user_complaint.html', {'user_complaints': user_complaints})

    except Exception as e:
        messages.error(request, f"An error occurred while fetching user complaints: {str(e)}")
        return redirect('dashboard')


# View for Failed Login Attempts
@login_required
@user_passes_test(is_admin)
def failed_login_view(request):
    """View to display failed login attempts."""
    try:
        failed_logins = FailedLoginAttempt.objects.all().order_by('-attempt_time')
        return render(request, 'components/admin/failed_login.html', {'failed_logins': failed_logins})

    except Exception as e:
        messages.error(request, f"An error occurred while fetching failed login attempts: {str(e)}")
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
def create_ticket(request):
    # Check if the logged-in user is part of the Employee group
    if not request.user.groups.filter(name='Employee').exists():
        messages.error(request, "You do not have permission to create a ticket.")
        return redirect('home')  # Redirect to home or an appropriate page if not an Employee

    if request.method == 'POST':
        issue_type = request.POST.get('issue_type')
        description = request.POST.get('description')
        subject = request.POST.get('subject', 'No subject')  # Default to 'No subject' if not provided

        # Check if necessary fields are provided
        if not issue_type or not description:
            messages.error(request, "Issue Type and Description are required.")
            return redirect('create_ticket')  # Redirect back to the ticket creation page
        
        # Create the ticket and associate it with the logged-in user
        ticket = ITSupportTicket(
            user=request.user,
            issue_type=issue_type,
            description=description,
            subject=subject,
            status='Open'  # Set the ticket status to 'Open' initially
        )
        ticket.save()  # Save the ticket to the database

        messages.success(request, "Your ticket has been created successfully.")
        return redirect('ticket_list')  # Redirect to a list or detail view of the tickets
    else:
        return render(request, 'create_ticket.html')
# Attendance View
@login_required
def attendance(request):
    # Check if the user is in either Employee or Manager group
    if request.user.groups.filter(name='Employee').exists() or request.user.groups.filter(name='Manager').exists():
        # Get the user's attendance data
        user_attendance = Attendance.objects.filter(user=request.user)
        total_present = user_attendance.filter(status='Present').count()
        total_absent = user_attendance.filter(status='Absent').count()
        total_leave = user_attendance.filter(status='On Leave').count()
        total_wfh = user_attendance.filter(status='Work From Home').count()

        return render(request, 'aps/attendance.html', {
            'total_present': total_present,
            'total_absent': total_absent,
            'total_leave': total_leave,
            'total_wfh': total_wfh,
            'user_attendance': user_attendance
        })

    else:
        messages.error(request, "You do not have permission to access this page.")
        return redirect('home')  # Redirect to home page if the user is not authorized