from django.urls import path, include
from . import views
from django.urls import re_path
from . import consumers

# WebSocket URL pattern for the chat system
websocket_urlpatterns = [
    path('ws/chat/', consumers.ChatConsumer.as_asgi(), name='chat_ws'),
]

# Admin-specific URLs under 'portal/admin/'
admin_patterns = [
    # Admin-related views
    path('user-sessions/', views.user_sessions_view, name='user_sessions'),  # View all user sessions
    path('it_support_admin/', views.it_support_admin, name='it_support_admin'),  # IT support admin home
    path('ticket/<int:ticket_id>/', views.ticket_detail, name='ticket_detail'),  # View details of a ticket
    path('ticket/update/<int:ticket_id>/', views.update_ticket, name='update_ticket'),  # Update ticket details
    path('report/', views.report_view, name='report'),  # Admin report view
    path('reports/feature_usage/', views.feature_usage_view, name='feature_usage'),  # Feature usage report
    path('reports/projects_report/', views.projects_report_view, name='projects_report'),  # Projects report
    path('reports/system_errors/', views.system_error_view, name='system_errors'),  # System errors report
    path('reports/system_usage/', views.system_usage_view, name='system_usage'),  # System usage report
    # Leave-related URLs for Admin
    path('leave/requests/', views.view_leave_requests_admin, name='view_leave_requests_admin'),  # Admin view for leave requests
    # Project management URLs for Admin
    path('projects/', views.project_view, {'action': 'list'}, name='projects_list'),
    path('projects/create/', views.project_view, {'action': 'create'}, name='project_create'),
    path('projects/<int:project_id>/update/', views.project_view, {'action': 'update'}, name='project_update'),
    path('projects/<int:project_id>/delete/', views.project_view, {'action': 'delete'}, name='project_delete'),
    path('projects/<int:project_id>/assign/', views.project_view, {'action': 'assign'}, name='project_assign'),
    path('projects/<int:project_id>/', views.project_view, {'action': 'detail'}, name='project_detail'),

    path('attendance/', views.admin_attendance_view, name='attendance'),  # Admin attendance summary
]

# Employee-specific URLs under 'portal/employee/'
employee_patterns = [
    # Employee-related views
    path('attendance/', views.employee_attendance_view, name='attendance'),  # Employee attendance view
    path('it_support/', views.it_support_home, name='it_support_home'),  # IT support home for employee
    path('it_support/create_ticket/', views.create_ticket, name='create_ticket'),  # Create an IT support ticket
    path('it_support/change_password/', views.change_password, name='change_password'),  # Change password for employee
    path('timesheet/', views.timesheet_view, name='timesheet'),  # View timesheet for employee
    # Leave-related URLs for Employee
    path('leave/', views.leave_view, name='leave_view'),  # Employee leave dashboard
   ]

# HR specific URLs under 'portal/hr/'
hr_patterns = [
    # HR views for leave management
    path('leave/requests/', views.view_leave_requests_hr, name='view_leave_requests_hr'),
    path('leave/<int:leave_id>/<str:action>/', views.manage_leave_request_hr, name='manage_leave_hr'),
# Attendance-related URLs for HR
    path('attendance/', views.hr_attendance_view, name='attendance'),  # HR attendance summary
]

# Manager-specific URLs under 'portal/manager/'
manager_patterns = [
    # Manager views for leave management

    path('leave/requests/', views.view_leave_requests_hr, name='view_leave_requests_manager'),
    path('leave/<int:leave_id>/<str:action>/', views.manage_leave_request_manager, name='manage_leave_manager'),
    path('view_timesheets/', views.manager_view_timesheets, name='view_timesheets'),  # View team timesheets for manager
    path('assign_tasks/', views.assign_tasks, name='assign_tasks'),  # Manager assigns tasks to employees
    # Attendance-related URLs for Manager
    path('attendance/', views.manager_attendance_view, name='attendance'),  # Manager attendance view
]

# Main URL configuration for the project
urlpatterns = [
    # Authentication views
    path('', views.home_view, name='home'),  # Home page view
    path('login/', views.login_view, name='login'),  # Login page
    path('logout/', views.logout_view, name='logout'),  # Logout page
    path('set_password/<str:username>/', views.set_password_view, name='set_password'),  # Set password for a specific user
    
    # Chat-related views
    path('chats/', views.chat_view, name='chat_view'),  # Chat view for users
    path('messages/<str:recipient_username>/', views.load_messages, name='load_messages'),  # Load messages for a specific user
    path('send_message/', views.send_message, name='send_message'),  # Send a message
    
    # Dashboard view
    path('dashboard/', views.dashboard_view, name='dashboard'),  # Main dashboard view

    # Admin-specific URLs under 'portal/admin/'
    path('portal/admin/', include((admin_patterns, 'aps'), namespace='aps_admin')),  # Admin-related URLs
    
    # Employee-specific URLs under 'portal/employee/'
    path('portal/employee/', include((employee_patterns, 'aps'), namespace='aps_employee')),  # Employee-related URLs
    
    # HR/Manager-specific URLs under 'portal/hr_manager/'
    path('portal/hr/', include((hr_patterns, 'aps'), namespace='aps_hr')),  # HR-related URLs
    
    # Manager-specific URLs under 'portal/manager/'
    path('portal/manager/', include((manager_patterns, 'aps'), namespace='aps_manager')),  # Manager-related URLs
]
