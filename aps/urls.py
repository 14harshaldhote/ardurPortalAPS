from django.urls import path, include
from . import views

# Admin-specific URLs under 'portal/admin/'
admin_patterns = [
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
    path('it_support/', views.create_ticket, name='it_support'),  # IT support ticket submission (was previously 'it_support_view')
    path('reset_password/', views.reset_password, name='reset_password'),  # Employee password reset
    # path('ticket_status/', views.ticket_status, name='ticket_status'),  # Employee can view their ticket status
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
]
