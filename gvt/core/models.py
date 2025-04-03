from django.db import models
from django.utils import timezone

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
    latitude = models.FloatField(null=True, blank=True)
    longitude = models.FloatField(null=True, blank=True)
    browser_info = models.CharField(max_length=255, blank=True, null=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    device_info = models.CharField(max_length=255, blank=True, null=True)
    priority_score = models.FloatField(null=True, blank=True, default=0.0)  # New field for AI priority

    def calculate_priority_score(self):
        """Calculate a priority score based on various factors."""
        score = 0.0
        
        # Crime Type Weight
        high_priority_types = ['hacking', 'data_breach']
        medium_priority_types = ['phishing', 'malware']
        if self.crime_type in high_priority_types:
            score += 40
        elif self.crime_type in medium_priority_types:
            score += 20
        else:
            score += 10

        # Description Keywords
        urgent_keywords = ['urgent', 'critical', 'emergency', 'immediate']
        if any(keyword in self.description.lower() for keyword in urgent_keywords):
            score += 30

        # Evidence Files
        evidence_count = self.evidence_files.count()
        score += min(evidence_count * 5, 20)  # Cap at 20 points

        # Recency (days since incident)
        days_since_incident = (timezone.now() - self.incident_date).days
        if days_since_incident <= 1:
            score += 20
        elif days_since_incident <= 7:
            score += 10

        # Location/IP Clustering (simple heuristic: more reports from same IP)
        similar_ip_count = CybercrimeReport.objects.filter(ip_address=self.ip_address).count()
        score += min(similar_ip_count * 5, 20)  # Cap at 20 points

        self.priority_score = min(score, 100)  # Cap total score at 100
        self.save()

    def __str__(self):
        return f"Report {self.id} - {self.crime_type}"

    class Meta:
        ordering = ['-priority_score', '-submitted_at']  # Prioritize by score, then recency

def evidence_upload_path(instance, filename):
    return f"evidence/report_{instance.report.id}/{filename}"

class EvidenceFile(models.Model):
    report = models.ForeignKey(CybercrimeReport, on_delete=models.CASCADE, related_name='evidence_files')
    file = models.FileField(upload_to=evidence_upload_path)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Evidence for Report {self.report.id}"