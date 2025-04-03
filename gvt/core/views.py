from django.shortcuts import render, redirect
from .forms import CybercrimeReportForm
from .models import CybercrimeReport, EvidenceFile
from .models import CybercrimeReport, EvidenceFile, CRIME_TYPES  # Import CRIME_TYPES

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
            
            # Calculate priority score
            report.calculate_priority_score()
            
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

from django.contrib.auth import logout
from django.shortcuts import redirect

def logout_view(request):
    logout(request)
    return redirect('login')

from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import login as auth_login
from .EmailBackEnd import EmailBackEnd  # Assuming this is your custom backend

def login_view(request):
    if request.method == "POST":
        user = EmailBackEnd.authenticate(
            request,
            username=request.POST.get('email'),
            password=request.POST.get('password')
        )
        if user is not None:
            auth_login(request, user)
            # Redirect to a common dashboard regardless of groups
            return redirect('dashboard')  # Replace 'dashboard' with your actual dashboard URL name
        else:
            messages.error(request, "Invalid Login Credentials!")
            return render(request, 'login.html')
    else:
        return render(request, 'login.html')


def dashboard(request):
    reports = CybercrimeReport.objects.all()  # Ordered by priority_score due to Meta
    return render(request, 'dashboard.html', {
        'reports': reports,
        'CRIME_TYPES': CRIME_TYPES
    })

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
    
    
    
    from django.shortcuts import render, redirect
from django.http import HttpResponse
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
from openpyxl import Workbook
from openpyxl.utils import get_column_letter

# Existing views (report_cybercrime and export_report) remain unchanged
# Add this new view:

def export_all_data_to_excel(request):
    """
    Export all CybercrimeReport and EvidenceFile data to an Excel file.
    """
    # Create a workbook and sheets
    wb = Workbook()
    
    # Cybercrime Reports Sheet
    ws_reports = wb.active
    ws_reports.title = "Cybercrime Reports"
    
    # Define headers for CybercrimeReport
    report_headers = [
        "ID", "Crime Type", "Incident Date", "Description", "Reporter Name", 
        "Reporter Email", "Reporter Phone", "Additional Info", "Submitted At", 
        "Latitude", "Longitude", "Browser Info", "IP Address", "Device Info"
    ]
    ws_reports.append(report_headers)
    
    # Fetch all reports
    reports = CybercrimeReport.objects.all()
    for report in reports:
        ws_reports.append([
            report.id,
            report.get_crime_type_display(),  # Human-readable crime type
            report.incident_date.strftime('%Y-%m-%d %H:%M:%S') if report.incident_date else '',
            report.description,
            report.reporter_name or '',
            report.reporter_email or '',
            report.reporter_phone or '',
            report.additional_info or '',
            report.submitted_at.strftime('%Y-%m-%d %H:%M:%S') if report.submitted_at else '',
            report.latitude,
            report.longitude,
            report.browser_info or '',
            report.ip_address or '',
            report.device_info or ''
        ])
    
    # Evidence Files Sheet
    ws_evidence = wb.create_sheet(title="Evidence Files")
    
    # Define headers for EvidenceFile
    evidence_headers = ["Report ID", "File Name", "Uploaded At"]
    ws_evidence.append(evidence_headers)
    
    # Fetch all evidence files
    evidence_files = EvidenceFile.objects.all()
    for evidence in evidence_files:
        ws_evidence.append([
            evidence.report.id,
            evidence.file.name,
            evidence.uploaded_at.strftime('%Y-%m-%d %H:%M:%S') if evidence.uploaded_at else ''
        ])
    
    # Adjust column widths for readability
    for ws in [ws_reports, ws_evidence]:
        for col in range(1, ws.max_column + 1):
            column_letter = get_column_letter(col)
            ws.column_dimensions[column_letter].width = 20  # Adjust width as needed
    
    # Save to a BytesIO buffer
    buffer = io.BytesIO()
    wb.save(buffer)
    buffer.seek(0)
    
    # Create the HTTP response
    response = HttpResponse(
        buffer,
        content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )
    response['Content-Disposition'] = 'attachment; filename="Cybercrime_Data.xlsx"'
    
    return response