from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils import timezone
from .models import Investigator, Case, Device, Evidence, Tool, Analysis, LogEntry, Report
import hashlib
import os
from django.conf import settings
from subprocess import Popen  # For running forensic tools (placeholder)
# Uncomment the following if you use Celery:
# from .tasks import run_forensic_tool

# Dashboard view: Displays all cases for the logged-in investigator

from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import login as auth_login
from .EmailBackEnd import EmailBackEnd  # Assuming this is your custom backend

def login(request):
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
    
from django.contrib.auth import logout
from django.shortcuts import redirect

def logout_view(request):
    logout(request)
    return redirect('login')  # Replace 'login' with your actual login URL name

    
@login_required
def dashboard(request):
    investigator = get_object_or_404(Investigator, user=request.user)
    cases = Case.objects.filter(investigator=investigator)
    context = {
        'cases': cases,
        'investigator': investigator,
    }
    return render(request, 'dashboard.html', context)

# Create a new case
@login_required
def create_case(request):
    investigator = get_object_or_404(Investigator, user=request.user)
    if request.method == 'POST':
        case_id = request.POST.get('case_id')
        title = request.POST.get('title')
        description = request.POST.get('description', '')

        if Case.objects.filter(case_id=case_id).exists():
            messages.error(request, "Case ID already exists.")
        else:
            case = Case.objects.create(
                case_id=case_id,
                title=title,
                investigator=investigator,
                description=description,
            )
            LogEntry.objects.create(
                case=case,
                investigator=investigator,
                action='CREATE',
                details=f"Case {case_id} created."
            )
            messages.success(request, f"Case {case_id} created successfully.")
            return redirect('case_detail', case_id=case_id)
    
    return render(request, 'create_case.html')

# Case detail view: Shows case details, devices, and evidence
@login_required
def case_detail(request, case_id):
    case = get_object_or_404(Case, case_id=case_id)
    investigator = get_object_or_404(Investigator, user=request.user)
    if case.investigator != investigator:
        messages.error(request, "You do not have permission to view this case.")
        return redirect('dashboard')
    
    devices = case.devices.all()
    evidence = case.evidence.all()
    context = {
        'case': case,
        'devices': devices,
        'evidence': evidence,
    }
    return render(request, 'case_detail.html', context)

# Add a device to a case
@login_required
def add_device(request, case_id):
    case = get_object_or_404(Case, case_id=case_id)
    investigator = get_object_or_404(Investigator, user=request.user)
    if case.investigator != investigator:
        return redirect('dashboard')

    if request.method == 'POST':
        device_type = request.POST.get('device_type')
        serial_number = request.POST.get('serial_number', '')
        description = request.POST.get('description', '')
        custodian = request.POST.get('custodian', '')

        device = Device.objects.create(
            case=case,
            device_type=device_type,
            serial_number=serial_number,
            description=description,
            custodian=custodian,
        )
        LogEntry.objects.create(
            case=case,
            investigator=investigator,
            action='CREATE',
            details=f"Device {device_type} ({serial_number}) added."
        )
        messages.success(request, "Device added successfully.")
        return redirect('case_detail', case_id=case_id)
    
    return render(request, 'add_device.html', {'case': case})

# Acquire evidence (e.g., upload a disk image)
@login_required
def acquire_evidence(request, case_id):
    case = get_object_or_404(Case, case_id=case_id)
    investigator = get_object_or_404(Investigator, user=request.user)
    if case.investigator != investigator:
        return redirect('dashboard')

    if request.method == 'POST':
        evidence_type = request.POST.get('evidence_type')
        file = request.FILES.get('file')
        description = request.POST.get('description', '')
        device_id = request.POST.get('device', None)

        # Compute hashes
        file_content = file.read()
        hash_md5 = hashlib.md5(file_content).hexdigest()
        hash_sha256 = hashlib.sha256(file_content).hexdigest()

        evidence = Evidence.objects.create(
            case=case,
            device=Device.objects.get(id=device_id) if device_id else None,
            evidence_type=evidence_type,
            file_path=file,
            hash_md5=hash_md5,
            hash_sha256=hash_sha256,
            size=file.size,
            description=description,
        )
        LogEntry.objects.create(
            case=case,
            evidence=evidence,
            investigator=investigator,
            action='CREATE',
            details=f"Evidence {evidence_type} acquired."
        )
        messages.success(request, "Evidence acquired successfully.")
        return redirect('case_detail', case_id=case_id)
    
    devices = case.devices.all()
    return render(request, 'acquire_evidence.html', {'case': case, 'devices': devices})

# Run an analysis on evidence
@login_required
def run_analysis(request, evidence_id):
    evidence = get_object_or_404(Evidence, id=evidence_id)
    investigator = get_object_or_404(Investigator, user=request.user)
    if evidence.case.investigator != investigator:
        return redirect('dashboard')

    if request.method == 'POST':
        tool_id = request.POST.get('tool')
        notes = request.POST.get('notes', '')
        tool = get_object_or_404(Tool, id=tool_id)

        analysis = Analysis.objects.create(
            evidence=evidence,
            tool=tool,
            investigator=investigator,
            status='PENDING',
            notes=notes,
        )
        LogEntry.objects.create(
            case=evidence.case,
            evidence=evidence,
            investigator=investigator,
            action='ANALYZE',
            details=f"Analysis started with {tool.name}."
        )

        # Placeholder for running a forensic tool (e.g., via subprocess or Celery)
        # Example with subprocess (replace with actual tool path):
        tool_script = os.path.join(settings.BASE_DIR, 'tools', f"{tool.name.lower()}.py")
        if os.path.exists(tool_script):
            Popen(['python', tool_script, str(evidence.file_path)])
        # With Celery:
        # run_forensic_tool.delay(analysis.id, evidence.file_path, tool.name)

        messages.success(request, f"Analysis with {tool.name} started.")
        return redirect('case_detail', case_id=evidence.case.case_id)
    
    tools = Tool.objects.all()
    return render(request, 'run_analysis.html', {'evidence': evidence, 'tools': tools})

# Generate a report for a case
@login_required
def generate_report(request, case_id):
    case = get_object_or_404(Case, case_id=case_id)
    investigator = get_object_or_404(Investigator, user=request.user)
    if case.investigator != investigator:
        return redirect('dashboard')

    if request.method == 'POST':
        title = request.POST.get('title')
        summary = request.POST.get('summary', '')

        # Placeholder for report generation (e.g., PDF creation)
        report_file = f"reports/{case_id}_{timezone.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        report_path = os.path.join(settings.MEDIA_ROOT, report_file)
        with open(report_path, 'w') as f:
            f.write(f"Report for {case.title}\nSummary: {summary}")  # Replace with actual PDF logic

        report = Report.objects.create(
            case=case,
            investigator=investigator,
            title=title,
            file_path=report_file,
            summary=summary,
        )
        LogEntry.objects.create(
            case=case,
            investigator=investigator,
            action='CREATE',
            details=f"Report {title} generated."
        )
        messages.success(request, "Report generated successfully.")
        return redirect('case_detail', case_id=case_id)
    
    return render(request, 'generate_report.html', {'case': case})

# views.py
from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required
import sqlite3
import pandas as pd
from .models import Case, Evidence

# views.py
# ... (previous imports remain the same)

@login_required
def database_forensics(request, case_id):
    case = get_object_or_404(Case, case_id=case_id)
    evidence_list = Evidence.objects.filter(case=case, evidence_type='OTHER')
    evidence_id = request.GET.get('evidence_id')
    analysis_results = None

    if evidence_id:
        evidence = get_object_or_404(Evidence, id=evidence_id, case=case)
        try:
            db_path = evidence.file_path.path
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [row[0] for row in cursor.fetchall()]

            table_data = {}
            for table in tables:
                df = pd.read_sql_query(f"SELECT * FROM {table}", conn)
                # Convert sample rows to a list of values instead of dictionaries
                sample_rows = [list(row) for row in df.head(5).itertuples(index=False, name=None)]
                table_data[table] = {
                    'columns': df.columns.tolist(),
                    'row_count': len(df),
                    'sample': sample_rows
                }

            cursor.execute("PRAGMA freelist_count;")
            free_pages = cursor.fetchone()[0]

            analysis_results = {
                'tables': table_data,
                'free_pages': free_pages,
                'file_size': evidence.size,
                'hash_md5': evidence.hash_md5,
                'hash_sha256': evidence.hash_sha256,
            }

            conn.close()
        except Exception as e:
            analysis_results = {'error': str(e)}

    context = {
        'case': case,
        'evidence_list': evidence_list,
        'analysis_results': analysis_results,
    }
    return render(request, 'database_forensics.html', context)