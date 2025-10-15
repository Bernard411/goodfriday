from django.db import models
from django.utils import timezone
from django.contrib.auth.models import User
from django.contrib.contenttypes.models import ContentType
from django.contrib.contenttypes.fields import GenericForeignKey

CRIME_TYPES = (
    ('phishing', 'Phishing'),
    ('hacking', 'Hacking'),
    ('malware', 'Malware'),
    ('identity_theft', 'Identity Theft'),
    ('cyberbullying', 'Cyberbullying'),
    ('online_fraud', 'Online Fraud'),
    ('data_breach', 'Data Breach'),
    ('others', 'Others'),
)

class CybercrimeReport(models.Model):
    crime_type = models.CharField(max_length=20, choices=CRIME_TYPES)
    incident_date = models.DateTimeField()
    description = models.TextField()
    reporter_name = models.CharField(max_length=100, blank=True, null=True)
    reporter_email = models.EmailField(blank=True, null=True)
    reporter_phone = models.CharField(max_length=15, blank=True, null=True)
    additional_info = models.TextField(blank=True, null=True)
    submitted_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    latitude = models.FloatField(null=True, blank=True)
    longitude = models.FloatField(null=True, blank=True)
    browser_info = models.CharField(max_length=255, blank=True, null=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    device_info = models.CharField(max_length=255, blank=True, null=True)
    priority_score = models.FloatField(null=True, blank=True, default=0.0)
    
    PRIORITY_LEVELS = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
    ]
    priority_level = models.CharField(max_length=20, choices=PRIORITY_LEVELS, default='medium')
    ai_analysis = models.JSONField(default=dict, blank=True)
    is_resolved = models.BooleanField(default=False)
    resolution_date = models.DateTimeField(null=True, blank=True)
    
    # Tracking fields
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='reports_created')
    updated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='reports_updated')
    resolved_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='reports_resolved')

    def calculate_priority_score(self):
        """Calculate a priority score based on enhanced AI analysis."""
        score = 0.0
        score_breakdown = {}
        
        crime_weights = {
            'data_breach': 45,
            'hacking': 40,
            'malware': 35,
            'phishing': 30,
            'identity_theft': 35,
            'cyberbullying': 25,
            'online_fraud': 30,
            'others': 20
        }
        
        crime_score = crime_weights.get(self.crime_type, 20)
        score += crime_score
        score_breakdown['crime_type'] = {
            'score': crime_score,
            'detail': f"Crime type '{self.crime_type}' base weight"
        }
        
        urgent_keywords = ['urgent', 'critical', 'emergency', 'immediate', 'danger', 'threat']
        impact_keywords = ['multiple', 'victims', 'financial', 'loss', 'sensitive', 'data']
        vulnerability_keywords = ['children', 'elderly', 'disabled', 'vulnerable']
        
        description_lower = self.description.lower()
        
        found_urgent = [k for k in urgent_keywords if k in description_lower]
        urgency_score = len(found_urgent) * 10
        score += urgency_score
        score_breakdown['urgency'] = {
            'score': urgency_score,
            'detail': f"Found urgent keywords: {', '.join(found_urgent) if found_urgent else 'none'}"
        }
        
        found_impact = [k for k in impact_keywords if k in description_lower]
        impact_score = len(found_impact) * 8
        score += impact_score
        score_breakdown['impact'] = {
            'score': impact_score,
            'detail': f"Found impact keywords: {', '.join(found_impact) if found_impact else 'none'}"
        }
        
        found_vuln = [k for k in vulnerability_keywords if k in description_lower]
        vuln_score = len(found_vuln) * 12
        score += vuln_score
        score_breakdown['vulnerability'] = {
            'score': vuln_score,
            'detail': f"Found vulnerability keywords: {', '.join(found_vuln) if found_vuln else 'none'}"
        }
        
        time_diff = timezone.now() - self.incident_date
        time_score = 0
        if time_diff.days < 1:
            time_score = 20
        elif time_diff.days < 7:
            time_score = 10
        score += time_score
        score_breakdown['time_factor'] = {
            'score': time_score,
            'detail': f"Incident is {time_diff.days} days old"
        }
            
        evidence_count = self.evidence_files.count()
        evidence_score = min(evidence_count * 5, 20)
        score += evidence_score
        score_breakdown['evidence'] = {
            'score': evidence_score,
            'detail': f"Number of evidence files: {evidence_count}"
        }
        
        score = min(max(score, 0), 100)
        
        self.priority_score = score
        if score >= 80:
            self.priority_level = 'critical'
        elif score >= 60:
            self.priority_level = 'high'
        elif score >= 40:
            self.priority_level = 'medium'
        else:
            self.priority_level = 'low'
            
        self.ai_analysis = {
            'total_score': score,
            'score_breakdown': score_breakdown,
            'calculation_time': timezone.now().isoformat(),
            'identified_keywords': [keyword for keyword in urgent_keywords + impact_keywords + vulnerability_keywords 
                                if keyword in description_lower]
        }
        
        self.save()
        return score

    def __str__(self):
        return f"Report {self.id} - {self.crime_type}"

    class Meta:
        ordering = ['-priority_score', '-submitted_at']

def evidence_upload_path(instance, filename):
    return f"evidence/report_{instance.report.id}/{filename}"

class EvidenceFile(models.Model):
    report = models.ForeignKey(CybercrimeReport, on_delete=models.CASCADE, related_name='evidence_files')
    file = models.FileField(upload_to=evidence_upload_path)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    uploaded_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)

    def __str__(self):
        return f"Evidence for Report {self.report.id}"


class ActivityLog(models.Model):
    """Track all activities in the system"""
    ACTION_TYPES = [
        ('create', 'Created'),
        ('update', 'Updated'),
        ('delete', 'Deleted'),
        ('view', 'Viewed'),
        ('export', 'Exported'),
        ('resolve', 'Resolved'),
        ('reopen', 'Reopened'),
        ('login', 'Login'),
        ('logout', 'Logout'),
        ('upload', 'File Uploaded'),
        ('download', 'File Downloaded'),
        ('priority_change', 'Priority Changed'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    action = models.CharField(max_length=20, choices=ACTION_TYPES)
    timestamp = models.DateTimeField(auto_now_add=True)
    
    # Generic relation to track any model
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE, null=True, blank=True)
    object_id = models.PositiveIntegerField(null=True, blank=True)
    content_object = GenericForeignKey('content_type', 'object_id')
    
    # Additional details
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    old_value = models.JSONField(null=True, blank=True)
    new_value = models.JSONField(null=True, blank=True)
    
    # Session tracking
    session_key = models.CharField(max_length=40, blank=True, null=True)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['-timestamp']),
            models.Index(fields=['user', '-timestamp']),
            models.Index(fields=['action', '-timestamp']),
        ]
    
    def __str__(self):
        user_str = self.user.username if self.user else 'Anonymous'
        return f"{user_str} - {self.get_action_display()} at {self.timestamp}"


class SystemMetrics(models.Model):
    """Track system-wide metrics and statistics"""
    date = models.DateField(unique=True)
    total_reports = models.IntegerField(default=0)
    reports_created = models.IntegerField(default=0)
    reports_resolved = models.IntegerField(default=0)
    reports_updated = models.IntegerField(default=0)
    average_priority_score = models.FloatField(default=0.0)
    critical_reports = models.IntegerField(default=0)
    high_priority_reports = models.IntegerField(default=0)
    medium_priority_reports = models.IntegerField(default=0)
    low_priority_reports = models.IntegerField(default=0)
    unique_users = models.IntegerField(default=0)
    total_evidence_files = models.IntegerField(default=0)
    
    class Meta:
        ordering = ['-date']
        verbose_name_plural = "System Metrics"
    
    def __str__(self):
        return f"Metrics for {self.date}"


class UserSession(models.Model):
    """Track user sessions for security and analytics"""
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    session_key = models.CharField(max_length=40, unique=True)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    login_time = models.DateTimeField(auto_now_add=True)
    logout_time = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    last_activity = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-login_time']
    
    def __str__(self):
        return f"{self.user.username} - {self.login_time}"
    
    def duration(self):
        """Calculate session duration"""
        if self.logout_time:
            return self.logout_time - self.login_time
        return timezone.now() - self.login_time


class ReportComment(models.Model):
    """Allow investigators to add comments to reports"""
    report = models.ForeignKey(CybercrimeReport, on_delete=models.CASCADE, related_name='comments')
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    comment = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_internal = models.BooleanField(default=True)  # Internal notes vs public updates
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"Comment on Report {self.report.id} by {self.user.username}"