from django.urls import path
from . import views

urlpatterns = [
    path('', views.report_cybercrime, name='report_cybercrime'),
  
    path('dashboard/', views.dashboard, name='dashboard'),
    path('delete/<int:report_id>/', views.delete_report, name='delete_report'),
    path('view/<int:report_id>/', views.view_report_analysis, name='view_report_analysis'),
]

