from django.shortcuts import render, redirect
from .forms import CybercrimeReportForm
from .models import CybercrimeReport, EvidenceFile

def report_cybercrime(request):
    """
    View to handle cybercrime report submission with multiple file uploads and metadata.
    """
    if request.method == 'POST':
        form = CybercrimeReportForm(request.POST, request.FILES)
        if form.is_valid():
            # Save the report without committing yet
            report = form.save(commit=False)
            
            # Add metadata from the request
            report.latitude = request.POST.get('latitude')
            report.longitude = request.POST.get('longitude')
            report.browser_info = request.POST.get('browser_info')
            report.device_info = request.POST.get('device_info')
            report.ip_address = request.META.get('REMOTE_ADDR')  # Capture IP address
            
            # Save the report to the database
            report.save()
            
            # Handle multiple file uploads
            files = request.FILES.getlist('evidence_files')
            for file in files:
                EvidenceFile.objects.create(report=report, file=file)
            
            return render(request, 'report_success.html', {'message': 'Report submitted successfully!'})
    else:
        form = CybercrimeReportForm()

    return render(request, 'report_cybercrime.html', {'form': form})


from django.shortcuts import render, redirect, get_object_or_404
from .models import CybercrimeReport, EvidenceFile
from .forms import CybercrimeReportForm
from django.contrib import messages


def dashboard(request):
    reports = CybercrimeReport.objects.all()
    return render(request, 'dashboard.html', {'reports': reports})

def delete_report(request, report_id):
    report = get_object_or_404(CybercrimeReport, id=report_id)
    if request.method == 'POST':
        report.delete()
        messages.success(request, 'Report deleted successfully!')
        return redirect('dashboard')
    return render(request, 'confirm_delete.html', {'report': report})

def view_report_analysis(request, report_id):
    report = get_object_or_404(CybercrimeReport, id=report_id)
    evidence_files = report.evidence_files.all()
    return render(request, 'report_analysis.html', {'report': report, 'evidence_files': evidence_files})