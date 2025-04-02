import os
import django
import random
from datetime import datetime, timedelta
from django.utils.timezone import make_aware

# Set up Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'gvt.settings')
django.setup()

from core.models import CybercrimeReport

# Sample data
descriptions = [
    "Phishing email received from an unknown source.",
    "Unauthorized access detected on the company’s network.",
    "Malware infection reported in the finance department.",
    "Personal information was stolen through a fake website.",
    "A student was harassed online through social media.",
    "Suspicious online transaction detected on a shopping site.",
    "Company database was exposed to the public.",
    "Unknown cybersecurity incident reported by a citizen.",
]

names = ["John Doe", "Jane Smith", "Robert Brown", "Alice Johnson", "Chris White"]
emails = ["john@example.com", "jane@example.com", "robert@example.com", "alice@example.com", "chris@example.com"]
phones = ["1234567890", "9876543210", "5556667777", "3334445555", "1112223333"]

# Generate 20 reports
for _ in range(20):
    report = CybercrimeReport.objects.create(
        crime_type=random.choice([choice[0] for choice in CybercrimeReport._meta.get_field('crime_type').choices]),
        incident_date=make_aware(datetime.now() - timedelta(days=random.randint(1, 365))),
        description=random.choice(descriptions),
        reporter_name=random.choice(names) if random.random() > 0.2 else None,
        reporter_email=random.choice(emails) if random.random() > 0.2 else None,
        reporter_phone=random.choice(phones) if random.random() > 0.2 else None,
        additional_info="No further details available." if random.random() > 0.5 else None,
    )
    print(f"Created report {report.id} - {report.crime_type}")

print("Successfully added 20 cybercrime reports!")
