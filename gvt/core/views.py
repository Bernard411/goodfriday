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


from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.conf import settings
from .forms import CybercrimeReportForm
from .models import CybercrimeReport, EvidenceFile
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, ListFlowable, ListItem, Image
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
import io
import os
import qrcode
from PIL import Image as PILImage

def report_cybercrime(request):
    if request.method == 'POST':
        form = CybercrimeReportForm(request.POST, request.FILES)
        if form.is_valid():
            report = form.save(commit=False)
            report.latitude = request.POST.get('latitude')
            report.longitude = request.POST.get('longitude')
            report.browser_info = request.POST.get('browser_info')
            report.device_info = request.POST.get('device_info')
            report.ip_address = request.META.get('REMOTE_ADDR')
            report.save()
            
            files = request.FILES.getlist('evidence_files')
            for file in files:
                EvidenceFile.objects.create(report=report, file=file)
            
            return render(request, 'report_success.html', {
                'message': 'Report submitted successfully!',
                'report': report,
                'evidence_files': report.evidence_files.all()
            })
    else:
        form = CybercrimeReportForm()

    return render(request, 'report_cybercrime.html', {'form': form})

def export_report(request, report_id):
    """
    Export the report as a PDF file with a logo and QR code.
    """
    try:
        report = CybercrimeReport.objects.get(id=report_id)
        evidence_files = report.evidence_files.all()

        # Create a PDF response
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        styles = getSampleStyleSheet()
        elements = []

        # Add Logo
        logo_path = os.path.join(settings.STATICFILES_DIRS[0], 'mw.png')
        logo = Image(logo_path, width=1*inch, height=1*inch)  # Adjust size as needed
        elements.append(logo)
        elements.append(Spacer(1, 12))

        # Title
        elements.append(Paragraph(f"Report #{report.id} - {report.get_crime_type_display()}", styles['Title']))
        elements.append(Spacer(1, 12))

        # Generate QR Code
        qr = qrcode.QRCode(version=1, box_size=10, border=4)
        qr_data = f"https://goodfriday.pythonanywhere.com/{report.id}/"  # Replace with your actual report URL
        qr.add_data(qr_data)
        qr.make(fit=True)
        qr_img = qr.make_image(fill_color="black", back_color="white")
        qr_buffer = io.BytesIO()
        qr_img.save(qr_buffer, format="PNG")
        qr_buffer.seek(0)
        qr_image = Image(qr_buffer, width=1*inch, height=1*inch)  # Adjust size as needed
        elements.append(qr_image)
        elements.append(Spacer(1, 12))

        # Incident Details
        elements.append(Paragraph("Incident Details", styles['Heading2']))
        elements.append(Paragraph(f"Crime Type: {report.get_crime_type_display()}", styles['Normal']))
        elements.append(Paragraph(f"Incident Date: {report.incident_date.strftime('%B %d, %Y, %I:%M %p')}", styles['Normal']))
        elements.append(Paragraph(f"Description: {report.description}", styles['Normal']))
        elements.append(Spacer(1, 12))

        # Reporter Information
        elements.append(Paragraph("Reporter Information", styles['Heading2']))
        elements.append(Paragraph(f"Name: {report.reporter_name or 'Anonymous'}", styles['Normal']))
        elements.append(Paragraph(f"Email: {report.reporter_email or 'Not provided'}", styles['Normal']))
        elements.append(Paragraph(f"Phone: {report.reporter_phone or 'Not provided'}", styles['Normal']))
        location = f"{report.latitude}, {report.longitude}" if report.latitude and report.longitude else "Not provided"
        elements.append(Paragraph(f"Location: {location}", styles['Normal']))
        elements.append(Paragraph(f"Browser Info: {report.browser_info or 'Not captured'}", styles['Normal']))
        elements.append(Paragraph(f"Device Info: {report.device_info or 'Not captured'}", styles['Normal']))
        elements.append(Paragraph(f"IP Address: {report.ip_address or 'Not captured'}", styles['Normal']))
        elements.append(Paragraph(f"Additional Info: {report.additional_info or 'None'}", styles['Normal']))
        elements.append(Spacer(1, 12))

        # Evidence Files
        elements.append(Paragraph("Evidence Files", styles['Heading2']))
        if evidence_files:
            evidence_list = [ListItem(Paragraph(f"{evidence.file.name}", styles['Normal'])) for evidence in evidence_files]
            elements.append(ListFlowable(evidence_list, bulletType='bullet'))
        else:
            elements.append(Paragraph("No evidence files uploaded.", styles['Normal']))
        elements.append(Spacer(1, 12))

        # Analysis Summary
        elements.append(Paragraph("Analysis Summary", styles['Heading2']))
        if report.crime_type in ['hacking', 'data_breach']:
            elements.append(Paragraph("Severity: High - Immediate action recommended", styles['Normal']))
        elif report.crime_type in ['phishing', 'malware']:
            elements.append(Paragraph("Severity: Medium - Monitor and mitigate", styles['Normal']))
        else:
            elements.append(Paragraph("Severity: Low - Review and document", styles['Normal']))
        
        elements.append(Paragraph("Potential Impact:", styles['Normal']))
        impact_items = [
            "System integrity and security posture",
            "Data privacy and confidentiality",
            "User trust and organizational reputation"
        ]
        if report.crime_type in ['hacking', 'data_breach']:
            impact_items.append("Regulatory compliance and potential legal ramifications")
        elements.append(ListFlowable([ListItem(Paragraph(item, styles['Normal'])) for item in impact_items], bulletType='bullet'))
        
        elements.append(Paragraph("Recommended Actions:", styles['Normal']))
        action_items = [
            "Investigate incident details and scope of impact",
            "Isolate affected systems if applicable",
            "Document findings and update security protocols",
            "Implement preventive measures to avoid recurrence"
        ]
        if report.crime_type in ['hacking', 'data_breach']:
            action_items.extend([
                "Engage cybersecurity response team immediately",
                "Prepare notification to affected parties"
            ])
        elements.append(ListFlowable([ListItem(Paragraph(item, styles['Normal'])) for item in action_items], bulletType='bullet'))

        # Build the PDF
        doc.build(elements)
        buffer.seek(0)
        
        # Serve the PDF
        response = HttpResponse(buffer, content_type='application/pdf')
        response['Content-Disposition'] = f'attachment; filename="Report_{report.id}.pdf"'
        return response
    
    except CybercrimeReport.DoesNotExist:
        return HttpResponse("Report not found", status=404)