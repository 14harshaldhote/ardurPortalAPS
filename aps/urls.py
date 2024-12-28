from django.urls import path, include
from . import views

# Admin-specific URLs under 'portal/admin/'
admin_patterns = [
    # Admin-related views
    path('user-sessions/', views.user_sessions_view, name='user_sessions'),
    path('it_support_admin/', views.it_support_admin, name='it_support_admin'),
    path('ticket/<int:ticket_id>/', views.ticket_detail, name='ticket_detail'),
    path('ticket/update/<int:ticket_id>/', views.update_ticket, name='update_ticket'),
    path('report/', views.report_view, name='report'),  # Admin report page
    path('report/feature_usage/', views.feature_usage, name='feature_usage'),
    path('report/projects_report/', views.projects_report, name='projects_report'),
    path('report/system_errors/', views.system_errors, name='system_errors'),
    path('report/system_usage/', views.system_usage, name='system_usage'),
]

# Employee-specific URLs under 'portal/employee/'
employee_patterns = [
    # Employee-related views
    path('attendance/', views.attendance_view, name='attendance'),
    path('it_support/', views.it_support_home, name='it_support_home'),
    path('it_support/create_ticket/', views.create_ticket, name='create_ticket'),
    path('it_support/change_password/', views.change_password, name='change_password'),
    path('timesheet/', views.timesheet_view, name='timesheet'),
    path('leave_request/', views.leave_request_view, name='leave_request'),  # For employee leave requests
    path('view_leave_balance/', views.view_leave_balance, name='view_leave_balance'),  # For viewing leave balance
]

# HR/Manager-specific URLs under 'portal/hr_manager/'
hr_manager_patterns = [
    # HR and Manager-related views
    path('approve_leave/<int:leave_id>/', views.approve_leave, name='approve_leave'),  # For approving leave requests
    path('view_leave_requests/', views.view_leave_requests, name='view_leave_requests'),  # For viewing all leave requests
]

urlpatterns = [
    # Authentication views
    path('', views.home_view, name='home'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('set_password/<str:username>/', views.set_password_view, name='set_password'),

    # Dashboard view
    path('dashboard/', views.dashboard_view, name='dashboard'),

    # Admin-specific URLs under 'portal/admin/'
    path('portal/admin/', include((admin_patterns, 'aps'), namespace='aps_admin')),  # Admin URLs

    # Employee-specific URLs under 'portal/employee/'
    path('portal/employee/', include((employee_patterns, 'aps'), namespace='aps_employee')),  # Employee URLs

    # HR/Manager-specific URLs under 'portal/hr_manager/'
    path('portal/hr_manager/', include((hr_manager_patterns, 'aps'), namespace='aps_hr_manager')),  # HR/Manager URLs
]
