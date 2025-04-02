from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone

# Investigator: Represents law enforcement personnel using the toolkit
class Investigator(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)  # Links to Django's built-in User model
    badge_number = models.CharField(max_length=20, unique=True, help_text="Unique ID for the investigator")
    agency = models.CharField(max_length=100, help_text="Law enforcement agency name")
    contact_email = models.EmailField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} ({self.badge_number})"

# Case: Represents a forensic investigation case
class Case(models.Model):
    STATUS_CHOICES = (
        ('OPEN', 'Open'),
        ('IN_PROGRESS', 'In Progress'),
        ('CLOSED', 'Closed'),
    )
    
    case_id = models.CharField(max_length=50, unique=True, help_text="Unique case identifier")
    title = models.CharField(max_length=200, help_text="Short description of the case")
    investigator = models.ForeignKey(Investigator, on_delete=models.SET_NULL, null=True, related_name="cases")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='OPEN')
    description = models.TextField(blank=True, help_text="Detailed case notes")

    def __str__(self):
        return f"{self.case_id} - {self.title}"

# Device: Represents a physical device (e.g., phone, hard drive) involved in a case
class Device(models.Model):
    DEVICE_TYPES = (
        ('HDD', 'Hard Drive'),
        ('SSD', 'Solid State Drive'),
        ('USB', 'USB Drive'),
        ('PHONE', 'Mobile Phone'),
        ('TABLET', 'Tablet'),
        ('OTHER', 'Other'),
    )

    case = models.ForeignKey(Case, on_delete=models.CASCADE, related_name="devices")
    device_type = models.CharField(max_length=20, choices=DEVICE_TYPES, default='HDD')
    serial_number = models.CharField(max_length=100, blank=True, help_text="Device serial number")
    description = models.TextField(blank=True, help_text="Device details, e.g., make, model")
    acquired_at = models.DateTimeField(default=timezone.now, help_text="When the device was seized")
    custodian = models.CharField(max_length=100, blank=True, help_text="Person who provided the device")

    def __str__(self):
        return f"{self.device_type} ({self.serial_number}) - Case {self.case.case_id}"

# Evidence: Represents a piece of digital evidence (e.g., disk image, recovered file)
class Evidence(models.Model):
    EVIDENCE_TYPES = (
        ('IMAGE', 'Disk Image'),
        ('FILE', 'Recovered File'),
        ('LOG', 'System Log'),
        ('MEMORY', 'Memory Dump'),
        ('NETWORK', 'Network Capture'),
        ('OTHER', 'Other'),
    )

    case = models.ForeignKey(Case, on_delete=models.CASCADE, related_name="evidence")
    device = models.ForeignKey(Device, on_delete=models.SET_NULL, null=True, blank=True, related_name="evidence")
    evidence_type = models.CharField(max_length=20, choices=EVIDENCE_TYPES, default='IMAGE')
    file_path = models.FileField(upload_to='evidence/%Y/%m/%d/', help_text="Path to the evidence file")
    hash_md5 = models.CharField(max_length=32, blank=True, help_text="MD5 hash of the evidence")
    hash_sha256 = models.CharField(max_length=64, blank=True, help_text="SHA-256 hash of the evidence")
    size = models.BigIntegerField(blank=True, null=True, help_text="File size in bytes")
    created_at = models.DateTimeField(auto_now_add=True)
    description = models.TextField(blank=True, help_text="Details about the evidence")

    def __str__(self):
        return f"{self.evidence_type} - Case {self.case.case_id}"

# Tool: Represents a forensic tool or process used in the investigation
class Tool(models.Model):
    TOOL_TYPES = (
        ('IMAGING', 'Disk Imaging'),
        ('RECOVERY', 'File Recovery'),
        ('CARVING', 'Data Carving'),
        ('MEMORY', 'Memory Analysis'),
        ('NETWORK', 'Network Analysis'),
        ('LOG', 'Log Analysis'),
        ('OTHER', 'Other'),
    )

    name = models.CharField(max_length=100, unique=True, help_text="Name of the tool or process")
    tool_type = models.CharField(max_length=20, choices=TOOL_TYPES, default='IMAGING')
    version = models.CharField(max_length=20, blank=True, help_text="Tool version")
    description = models.TextField(blank=True, help_text="Tool purpose and capabilities")

    def __str__(self):
        return f"{self.name} ({self.tool_type})"

# Analysis: Represents the use of a tool on a piece of evidence
class Analysis(models.Model):
    STATUS_CHOICES = (
        ('PENDING', 'Pending'),
        ('RUNNING', 'Running'),
        ('COMPLETED', 'Completed'),
        ('FAILED', 'Failed'),
    )

    evidence = models.ForeignKey(Evidence, on_delete=models.CASCADE, related_name="analyses")
    tool = models.ForeignKey(Tool, on_delete=models.SET_NULL, null=True, related_name="analyses")
    investigator = models.ForeignKey(Investigator, on_delete=models.SET_NULL, null=True, related_name="analyses")
    start_time = models.DateTimeField(default=timezone.now)
    end_time = models.DateTimeField(blank=True, null=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PENDING')
    output_path = models.FileField(upload_to='analysis/%Y/%m/%d/', blank=True, null=True, help_text="Path to analysis results")
    notes = models.TextField(blank=True, help_text="Analysis observations")

    def __str__(self):
        return f"{self.tool.name} on {self.evidence} - {self.status}"

# LogEntry: Tracks actions for chain-of-custody and auditing
class LogEntry(models.Model):
    ACTION_TYPES = (
        ('CREATE', 'Created'),
        ('ACCESS', 'Accessed'),
        ('MODIFY', 'Modified'),
        ('DELETE', 'Deleted'),
        ('ANALYZE', 'Analyzed'),
    )

    case = models.ForeignKey(Case, on_delete=models.CASCADE, related_name="logs")
    evidence = models.ForeignKey(Evidence, on_delete=models.CASCADE, null=True, blank=True, related_name="logs")
    investigator = models.ForeignKey(Investigator, on_delete=models.SET_NULL, null=True, related_name="logs")
    action = models.CharField(max_length=20, choices=ACTION_TYPES, default='CREATE')
    timestamp = models.DateTimeField(default=timezone.now)
    details = models.TextField(blank=True, help_text="Details of the action")

    def __str__(self):
        return f"{self.action} - {self.case.case_id} at {self.timestamp}"

# Report: Represents a generated report for a case
class Report(models.Model):
    case = models.ForeignKey(Case, on_delete=models.CASCADE, related_name="reports")
    investigator = models.ForeignKey(Investigator, on_delete=models.SET_NULL, null=True, related_name="reports")
    title = models.CharField(max_length=200, help_text="Report title")
    file_path = models.FileField(upload_to='reports/%Y/%m/%d/', help_text="Path to the generated report file")
    created_at = models.DateTimeField(auto_now_add=True)
    summary = models.TextField(blank=True, help_text="Executive summary of findings")

    def __str__(self):
        return f"{self.title} - Case {self.case.case_id}"