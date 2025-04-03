from django.urls import path
from . import views
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('', views.report_cybercrime, name='report_cybercrime'),
  
    path('dashboard/', views.dashboard, name='dashboard'),
    path('delete/<int:report_id>/', views.delete_report, name='delete_report'),
    path('export-report/<int:report_id>/', views.export_report, name='export_report'),
    path('view/<int:report_id>/', views.view_report_analysis, name='view_report_analysis'),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

