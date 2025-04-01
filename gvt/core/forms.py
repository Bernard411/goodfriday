from django import forms
from .models import CybercrimeReport, EvidenceFile

class CybercrimeReportForm(forms.ModelForm):
    """
    Form for submitting a cybercrime report.
    """
    class Meta:
        model = CybercrimeReport
        fields = [
            'crime_type', 'incident_date', 'description',
            'reporter_name', 'reporter_email', 'reporter_phone', 'additional_info'
        ]
        widgets = {
            'incident_date': forms.DateTimeInput(attrs={'type': 'datetime-local'}),
            'description': forms.Textarea(attrs={'rows': 5}),
            'additional_info': forms.Textarea(attrs={'rows': 3}),
        }

class EvidenceFileForm(forms.ModelForm):
    """
    Form for uploading evidence files.
    """
    class Meta:
        model = EvidenceFile
        fields = ['file']

# For handling multiple file uploads
EvidenceFileFormSet = forms.inlineformset_factory(
    CybercrimeReport,
    EvidenceFile,
    form=EvidenceFileForm,
    extra=1,  # Start with 1 file upload field
    can_delete=False,
)