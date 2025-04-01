from django.shortcuts import render, redirect
from .forms import CybercrimeReportForm
from .models import CybercrimeReport, EvidenceFile

def report_cybercrime(request):
    """
    View to handle cybercrime report submission with multiple file uploads.
    """
    if request.method == 'POST':
        form = CybercrimeReportForm(request.POST, request.FILES)
        if form.is_valid():
            # Save the report
            report = form.save()
            # Handle multiple file uploads
            files = request.FILES.getlist('evidence_files')
            for file in files:
                EvidenceFile.objects.create(report=report, file=file)
            return render(request, 'report_success.html', {'message': 'Report submitted successfully!'})
    else:
        form = CybercrimeReportForm()

    return render(request, 'report_cybercrime.html', {'form': form})