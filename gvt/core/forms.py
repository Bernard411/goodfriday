from django import forms
from .models import CybercrimeReport, EvidenceFile
from django import forms
from .models import CybercrimeReport, EvidenceFile

class CybercrimeReportForm(forms.ModelForm):
    class Meta:
        model = CybercrimeReport
        fields = [
            'crime_type', 'incident_date', 'description',
            'reporter_name', 'reporter_email', 'reporter_phone', 'additional_info'
        ]
        widgets = {
            'crime_type': forms.Select(attrs={'class': 'form-control'}),
            'incident_date': forms.DateTimeInput(attrs={'type': 'datetime-local', 'class': 'form-control'}),
            'description': forms.Textarea(attrs={'rows': 5, 'class': 'form-control'}),
            'reporter_name': forms.TextInput(attrs={'class': 'form-control'}),
            'reporter_email': forms.EmailInput(attrs={'class': 'form-control'}),
            'reporter_phone': forms.TextInput(attrs={'class': 'form-control'}),
            'additional_info': forms.Textarea(attrs={'rows': 3, 'class': 'form-control'}),
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