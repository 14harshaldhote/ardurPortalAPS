from django.urls import path, include
from . import views
from django.urls import re_path
from . import consumers

websocket_urlpatterns = [
    path('ws/chat/', consumers.ChatConsumer.as_asgi(), name='chat_ws'),
]

# Admin-specific URLs under 'portal/admin/'
admin_patterns = [
    # Admin-related views
    path('user-sessions/', views.user_sessions_view, name='user_sessions'),
    path('it_support_admin/', views.it_support_admin, name='it_support_admin'),
    path('ticket/<int:ticket_id>/', views.ticket_detail, name='ticket_detail'),
    path('ticket/update/<int:ticket_id>/', views.update_ticket, name='update_ticket'),
    path('report/', views.report_view, name='report'),
    path('reports/feature_usage/', views.feature_usage_view, name='feature_usage'),
    path('reports/projects_report/', views.projects_report_view, name='projects_report'),
    path('reports/system_errors/', views.system_error_view, name='system_errors'),
    path('reports/system_usage/', views.system_usage_view, name='system_usage'),
    # Leave-related URLs for Admin
    path('view_leave_requests/', views.view_leave_requests_admin, name='view_leave_requests'),  # View all leave requests
    path('approve_leave/<int:leave_id>/', views.approve_leave, name='approve_leave'),  # Admin approves leave

    # Project management URLs for Admin
    path('projects/', views.project_management, name='project_management'),
    path('project/<int:project_id>/', views.view_project, name='view_project'),
    path('project_add/', views.project_view, name='add_project'),
    path('project/<int:project_id>/assign_manager/', views.assign_manager, name='assign_manager'),
    path('project/<int:project_id>/assign_employee/', views.assign_employee, name='assign_employee'),

    # Attendance-related URLs for Admin
    path('attendance/', views.admin_attendance_view, name='attendance'),  # Admin attendance summary
]

# Employee-specific URLs under 'portal/employee/'
employee_patterns = [
    # Employee-related views
    path('attendance/', views.employee_attendance_view, name='attendance'),  # Employee attendance view
    path('it_support/', views.it_support_home, name='it_support_home'),
    path('it_support/create_ticket/', views.create_ticket, name='create_ticket'),
    path('it_support/change_password/', views.change_password, name='change_password'),
    path('timesheet/', views.timesheet_view, name='timesheet'),

    # Leave-related URLs for Employee
    path('leave_request/', views.leave_request_view, name='leave_request'),  # For employee leave requests
    path('view_leave_balance/', views.view_leave_balance_employee, name='view_leave_balance'),  # For viewing leave balance
]

# HR specific URLs under 'portal/hr/'
hr_patterns = [
    # HR and Manager-related views
    path('approve_leave/<int:leave_id>/', views.approve_leave_hr, name='approve_leave'),  # For HR to approve leave
    path('view_leave_requests/', views.view_leave_requests_hr, name='view_leave_requests'),  # For HR to view all leave requests

    # Attendance-related URLs for HR
    path('attendance/', views.hr_attendance_view, name='attendance'),  # HR attendance view
   ]   

manager_patterns = [
    # Manager-specific leave views
    path('approve_leave/<int:leave_id>/', views.approve_leave_manager, name='approve_leave'),  # For manager to approve leave
    path('view_leave_requests/', views.view_leave_requests_manager, name='view_leave_requests'),
    path('view_timesheets/', views.manager_view_timesheets, name='view_timesheets'),  # For manager to view leave requests for their team
    path('assign_tasks/', views.assign_tasks, name='assign_tasks'),  # For manager to assign tasks to employees

    # Attendance-related URLs for Manager
    path('attendance/', views.manager_attendance_view, name='attendance'),  # Manager attendance view
]

urlpatterns = [
    # Authentication views
    path('', views.home_view, name='home'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('set_password/<str:username>/', views.set_password_view, name='set_password'),

    
    path('chats/', views.chat_view, name='chat_view'),
    path('messages/<str:recipient_username>/', views.load_messages, name='load_messages'),
    path('send_message/', views.send_message, name='send_message'),

    path('break/start/<str:break_type>/', views.start_break, name='start_break'),
    path('break/end/<int:break_id>/', views.end_break, name='end_break'),
    path('break/submit-reason/<int:break_id>/', views.submit_reason, name='submit_break_reason'),

    path('break_management/', views.break_management, name='break_management'),
 # path('chats/<int:chat_id>/send/', views.chat_view, name='send-message'),
    # Dashboard view
    path('dashboard/', views.dashboard_view, name='dashboard'),

    # Admin-specific URLs under 'portal/admin/'
    path('portal/admin/', include((admin_patterns, 'aps'), namespace='aps_admin')),  # Admin URLs

    # Employee-specific URLs under 'portal/employee/'
    path('portal/employee/', include((employee_patterns, 'aps'), namespace='aps_employee')),  # Employee URLs

    # HR/Manager-specific URLs under 'portal/hr_manager/'
    path('portal/hr/', include((hr_patterns, 'aps'), namespace='aps_hr')),  # HR URLs

    # Manager-specific URLs under 'portal/manager/'
    path('portal/manager/', include((manager_patterns, 'aps'), namespace='aps_manager')),  # Manager URLs
]
