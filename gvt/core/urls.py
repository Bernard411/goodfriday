from django.urls import path
from . import views
from django.conf import settings
from .views import logout_view
from django.conf.urls.static import static

from django.urls import path
from django.contrib.auth import views as auth_views
from . import views

urlpatterns = [
    # ============= AUTHENTICATION URLS =============
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    
    # ============= REPORT CRUD URLS =============
    path('report/', views.report_cybercrime, name='report_cybercrime'),
    path('report/success/<int:report_id>/', views.report_success, name='success'),
    path('report/edit/<int:report_id>/', views.edit_report, name='edit_report'),
    path('report/delete/<int:report_id>/', views.delete_report, name='delete_report'),
    
    # ============= DASHBOARD AND ANALYSIS URLS =============
    path('dashboard/', views.dashboard, name='dashboard'),
    path('priority-dashboard/', views.priority_dashboard, name='priority_dashboard'),
    path('report/analysis/<int:report_id>/', views.view_report_analysis, name='view_report_analysis'),
    path('report/status/<int:report_id>/', views.update_report_status, name='update_report_status'),
    
    # ============= COMMENT URLS =============
    path('report/comment/<int:report_id>/', views.add_comment, name='add_comment'),
    path('comment/edit/<int:comment_id>/', views.edit_comment, name='edit_comment'),
    path('comment/delete/<int:comment_id>/', views.delete_comment, name='delete_comment'),
    
    # ============= EXPORT URLS =============
    path('report/export/<int:report_id>/', views.export_report, name='export_report'),
    path('export/all/', views.export_all_data_to_excel, name='export_all_data'),
    
    # ============= STATISTICS AND ANALYTICS URLS =============
    path('statistics/', views.statistics_view, name='statistics'),
    path('activity-log/', views.activity_log_view, name='activity_log'),
    path('user-sessions/', views.user_sessions_view, name='user_sessions'),
    path('system-health/', views.system_health_view, name='system_health'),
    
    # ============= DEFAULT/REDIRECT URL =============
    path('', views.report_cybercrime, name='home'),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

