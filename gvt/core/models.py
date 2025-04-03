# from django.db import models

# CRIME_TYPES = (
#     ('phishing', 'Phishing'),
#     ('hacking', 'Hacking'),
#     ('malware', 'Malware'),
#     ('identity_theft', 'Identity Theft'),
#     ('cyberbullying', 'Cyberbullying'),
#     ('online_fraud', 'Online Fraud'),
#     ('data_breach', 'Data Breach'),
#     ('others', 'Others'),
# )

# class CybercrimeReport(models.Model):
#     crime_type = models.CharField(max_length=20, choices=CRIME_TYPES)
#     incident_date = models.DateTimeField()
#     description = models.TextField()
#     reporter_name = models.CharField(max_length=100, blank=True, null=True)
#     reporter_email = models.EmailField(blank=True, null=True)
#     reporter_phone = models.CharField(max_length=15, blank=True, null=True)
#     additional_info = models.TextField(blank=True, null=True)
#     submitted_at = models.DateTimeField(auto_now_add=True)

#     def __str__(self):
#         return f"Report {self.id} - {self.crime_type}"

#     class Meta:
#         ordering = ['-submitted_at']

# def evidence_upload_path(instance, filename):
#     return f"evidence/report_{instance.report.id}/{filename}"

# class EvidenceFile(models.Model):
#     report = models.ForeignKey(CybercrimeReport, on_delete=models.CASCADE, related_name='evidence_files')
#     file = models.FileField(upload_to=evidence_upload_path)
#     uploaded_at = models.DateTimeField(auto_now_add=True)

#     def __str__(self):
#         return f"Evidence for Report {self.report.id}"

from django.db import models

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
    
    # New fields for authenticity
    latitude = models.FloatField(null=True, blank=True)
    longitude = models.FloatField(null=True, blank=True)
    browser_info = models.CharField(max_length=255, blank=True, null=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    device_info = models.CharField(max_length=255, blank=True, null=True)

    def __str__(self):
        return f"Report {self.id} - {self.crime_type}"

    class Meta:
        ordering = ['-submitted_at']

def evidence_upload_path(instance, filename):
    return f"evidence/report_{instance.report.id}/{filename}"

class EvidenceFile(models.Model):
    report = models.ForeignKey(CybercrimeReport, on_delete=models.CASCADE, related_name='evidence_files')
    file = models.FileField(upload_to=evidence_upload_path)
    uploaded_at = models.DateTimeField(auto_now_add=True)  # Fixed typo: auto_now_adad -> auto_now_add

    def __str__(self):
        return f"Evidence for Report {self.report.id}"