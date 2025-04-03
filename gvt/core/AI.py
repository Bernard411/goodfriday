from sklearn.ensemble import RandomForestRegressor
from django.core.management.base import BaseCommand
import joblib

class Command(BaseCommand):
    def handle(self, *args, **options):
        reports = CybercrimeReport.objects.all()
        X = [[
            1 if r.crime_type in ['hacking', 'data_breach'] else 0.5 if r.crime_type in ['phishing', 'malware'] else 0,
            len(r.description),
            r.evidence_files.count(),
            (timezone.now() - r.incident_date).days,
            CybercrimeReport.objects.filter(ip_address=r.ip_address).count()
        ] for r in reports]
        y = [r.priority_score or 50 for r in reports]  # Use existing scores or default
        model = RandomForestRegressor()
        model.fit(X, y)
        joblib.dump(model, 'priority_model.pkl')