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
    path('report/', views.report_view, name='report'),  # Admin report view
    path('reports/feature_usage/', views.feature_usage_view, name='feature_usage'),  # Feature usage report
    path('reports/projects_report/', views.projects_report_view, name='projects_report'),  # Projects report
    path('reports/system_errors/', views.system_error_view, name='system_errors'),  # System errors report
    path('reports/system_usage/', views.system_usage_view, name='system_usage'),  # System usage report
    # Leave-related URLs for Admin
    path('leave/requests/', views.view_leave_requests_admin, name='view_leave_requests_admin'),  # Admin view for leave requests

    path('projects_dashboard/', views.project_dashboard, name='project_dashboard'),
    path('projects/create/', views.project_create, name='project_create'),
    path('projects/update/<int:project_id>/', views.project_update, name='project_update'),
    path('projects/<int:project_id>/delete/', views.project_delete, name='project_delete'),

    path('projects/<int:project_id>/assign/', views.assign_employee, name='assign_employee'),

    # Remove employee from project (soft delete)
    path('projects/<int:project_id>/remove/', views.assign_employee, name='remove_member'),

    # Reactivate previously removed employee
    path('projects/<int:project_id>/reactivate/', views.reactivate_employee, name='reactivate_member'),

    # Change role of an assigned employee
    path('projects/<int:project_id>/change-role/', views.change_role, name='change_role'),

    # Update project hours
    path('projects/<int:project_id>/update_hours/', views.update_hours, name='update_hours'),



 
    path('attendance/', views.admin_attendance_view, name='attendance'),  # Admin attendance summary

    path('support/', views.admin_support, name='admin_support'),
    path('support/<uuid:ticket_id>/', views.admin_support, name='admin_support_with_ticket'),

]

# Employee-specific URLs under 'portal/employee/'
employee_patterns = [
    # Employee-related views

    path('support/', views.employee_support, name='employee_support'),

    path('attendance/', views.employee_attendance_view, name='attendance'),  # Employee attendance view
   
    path('timesheet/', views.timesheet_view, name='timesheet'),  # View timesheet for employee
    # Leave-related URLs for Employee
    path('leave/', views.leave_view, name='leave_view'),  # Employee leave dashboard
   
    path('profile/', views.employee_profile, name='employee_profile'),
]

# HR specific URLs under 'portal/hr/'
hr_patterns = [
    # HR views for leave management
    path('leave/requests/', views.view_leave_requests_hr, name='view_leave_requests_hr'),
    path('leave/<int:leave_id>/<str:action>/', views.manage_leave_request_hr, name='manage_leave_hr'),
    path('attendance/', views.hr_attendance_view, name='attendance'),  # HR attendance summary
    path('userdetails/', views.hr_dashboard, name='hr_dashboard'),
    path('user/<int:user_id>/', views.hr_user_detail, name='hr_user_detail'),
    path('hr/support/', views.hr_support, name='hr_support'),
    path('hr/support/<uuid:ticket_id>/', views.hr_support, name='hr_support_with_ticket'),  
    path('hr/get-update/<int:update_id>/', views.get_update_data, name='get_update_data'),
    path('hr/create-update/', views.hr_create_update, name='hr_create_update'),
    path('hr/edit-update/<int:update_id>/', views.hr_edit_update, name='hr_edit_update'),
    path('hr/delete-update/<int:update_id>/', views.hr_delete_update, name='hr_delete_update'),


    path('employees/', views.employee_directory, name='employee_directory'),


]

# Manager-specific URLs under 'portal/manager/'
manager_patterns = [
    # Manager views for leave management
    path('projects/', views.manager_project_view, {'action': 'list'}, name='project_list'),  # List all projects
    path('projects/create/', views.manager_project_view, {'action': 'create'}, name='project_create'),  # Create project
    path('projects/update/<int:project_id>/', views.manager_project_view, {'action': 'update'}, name='project_update'),  # Update project
    path('projects/detail/<int:project_id>/', views.manager_project_view, {'action': 'detail'}, name='project_detail'),  # View project details
    
    path('employee/', views.manager_employee_profile, name='manager_employee_profile'),
    path('user/<int:user_id>/', views.manager_user_detail, name='manager_user_detail'),

    path('create-project-update/', views.manager_create_project_update, name='manager_create_project_update'),
    path('edit-project-update/<int:update_id>/', views.manager_edit_project_update, name='manager_edit_project_update'),
    path('delete-project-update/<int:update_id>/', views.manager_delete_project_update, name='manager_delete_project_update'),


    path('leave/requests/', views.view_leave_requests_manager, name='view_leave_requests_manager'),
    path('leave/<int:leave_id>/<str:action>/', views.manage_leave_request_manager, name='manage_leave_manager'),
    path('view_timesheets/', views.manager_view_timesheets, name='view_timesheets'), 
    path('bulk-update-timesheet/', views.bulk_update_timesheet, name='bulk_update_timesheet'),

 # View team timesheets for manager
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

    path('profile/<int:user_id>/', views.user_profile, name='user_profile'),
    
    path('update-last-activity/', views.update_last_activity, name='update_last_activity'),
    path('end-session/', views.end_session, name='end_session'),

    path('break/start/<str:break_type>/', views.start_break, name='start_break'),
    path('break/end/<int:break_id>/', views.end_break, name='end_break'),
    path('break/submit-reason/<int:break_id>/', views.submit_reason, name='submit_break_reason'),

    path('break_management/', views.break_management, name='break_management'),
 # path('chats/<int:chat_id>/send/', views.chat_view, name='send-message'),
    path('break/check/', views.check_active_break, name='check_active_break'),
    path('break/take/', views.take_break, name='take_break'),
    path('break/end/<int:break_id>/', views.end_break, name='end_break'),
    # Chat-related views
    path('chats/', views.chat_view, name='chat_view'),  # Chat view for users
    path('messages/<str:recipient_username>/', views.load_messages, name='load_messages'),  # Load messages for a specific user
    path('send_message/', views.send_message, name='send_message'),  # Send a message
    
    # Dashboard view
    path('dashboard/', views.dashboard_view, name='dashboard'),  # Main dashboard view

    # Admin-specific URLs under 'portal/admin/'
    path('portal/admin/', include((admin_patterns, 'aps'), namespace='aps_admin')),
    
    # Employee-specific URLs under 'portal/employee/'
    path('portal/employee/', include((employee_patterns, 'aps'), namespace='aps_employee')),  # Employee-related URLs
    
    # HR/Manager-specific URLs under 'portal/hr_manager/'
    path('portal/hr/', include((hr_patterns, 'aps'), namespace='aps_hr')),  # HR-related URLs
    
    # Manager-specific URLs under 'portal/manager/'
    path('portal/manager/', include((manager_patterns, 'aps'), namespace='aps_manager')),  # Manager-related URLs
]


