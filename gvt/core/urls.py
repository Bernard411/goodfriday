from django.urls import path
from . import views

urlpatterns = [
    path('', views.report_cybercrime, name='report_cybercrime'),
]