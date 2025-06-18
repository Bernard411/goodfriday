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

    def calculate_priority_score(self):
        """Calculate a priority score based on enhanced AI analysis."""
        score = 0.0
        score_breakdown = {}
        
        # Base weights for different factors
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
        
        # Crime Type Weight
        crime_score = crime_weights.get(self.crime_type, 20)
        score += crime_score
        score_breakdown['crime_type'] = {
            'score': crime_score,
            'detail': f"Crime type '{self.crime_type}' base weight"
        }
        
        # Description Analysis
        urgent_keywords = ['urgent', 'critical', 'emergency', 'immediate', 'danger', 'threat']
        impact_keywords = ['multiple', 'victims', 'financial', 'loss', 'sensitive', 'data']
        vulnerability_keywords = ['children', 'elderly', 'disabled', 'vulnerable']
        
        # Keyword scoring
        description_lower = self.description.lower()
        
        # Urgency score
        found_urgent = [k for k in urgent_keywords if k in description_lower]
        urgency_score = len(found_urgent) * 10
        score += urgency_score
        score_breakdown['urgency'] = {
            'score': urgency_score,
            'detail': f"Found urgent keywords: {', '.join(found_urgent) if found_urgent else 'none'}"
        }
        
        # Impact score
        found_impact = [k for k in impact_keywords if k in description_lower]
        impact_score = len(found_impact) * 8
        score += impact_score
        score_breakdown['impact'] = {
            'score': impact_score,
            'detail': f"Found impact keywords: {', '.join(found_impact) if found_impact else 'none'}"
        }
        
        # Vulnerability score
        found_vuln = [k for k in vulnerability_keywords if k in description_lower]
        vuln_score = len(found_vuln) * 12
        score += vuln_score
        score_breakdown['vulnerability'] = {
            'score': vuln_score,
            'detail': f"Found vulnerability keywords: {', '.join(found_vuln) if found_vuln else 'none'}"
        }
        
        # Time factor - newer incidents get higher priority
        time_diff = timezone.now() - self.incident_date
        time_score = 0
        if time_diff.days < 1:  # Last 24 hours
            time_score = 20
        elif time_diff.days < 7:  # Last week
            time_score = 10
        score += time_score
        score_breakdown['time_factor'] = {
            'score': time_score,
            'detail': f"Incident is {time_diff.days} days old"
        }
            
        # Evidence weight
        evidence_count = self.evidence_files.count()
        evidence_score = min(evidence_count * 5, 20)  # Up to 20 points for evidence
        score += evidence_score
        score_breakdown['evidence'] = {
            'score': evidence_score,
            'detail': f"Number of evidence files: {evidence_count}"
        }
        
        # Normalize score to 0-100 range
        score = min(max(score, 0), 100)
        
        # Update priority score and level
        self.priority_score = score
        if score >= 80:
            self.priority_level = 'critical'
        elif score >= 60:
            self.priority_level = 'high'
        elif score >= 40:
            self.priority_level = 'medium'
        else:
            self.priority_level = 'low'
            
        # Update AI analysis with detailed scoring breakdown
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
        ordering = ['-priority_score', '-submitted_at']  # Prioritize by score, then recency

def evidence_upload_path(instance, filename):
    return f"evidence/report_{instance.report.id}/{filename}"

class EvidenceFile(models.Model):
    report = models.ForeignKey(CybercrimeReport, on_delete=models.CASCADE, related_name='evidence_files')
    file = models.FileField(upload_to=evidence_upload_path)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Evidence for Report {self.report.id}"