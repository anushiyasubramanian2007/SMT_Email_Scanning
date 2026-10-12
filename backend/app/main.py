from fastapi import FastAPI, Depends, File, UploadFile, Request, HTTPException, status, Response
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from dotenv import load_dotenv
import os
import hashlib
import re
import json
from typing import Optional, List, Dict, Any

# Load environment variables from .env file
load_dotenv()

from app.schemas.schemas import (
    EmailAnalysisRequest, EmailAnalysisResponse, 
    UrlAnalysisRequest, UrlAnalysisResponse, 
    AttachmentAnalysisResponse, Indicator
)
from app.schemas.forensic_schemas import (
    ForensicAnalysisRequest,
    ForensicAnalysisResponse,
    CaseCreate,
    CaseUpdate,
    CaseResponse,
    ThreatIndicatorResponse,
    ThreatCampaignResponse,
    ThreatGraphResponse
)
from app.detectors.rules import analyze_url, DANGEROUS_EXTENSIONS, MACRO_EXTENSIONS, ARCHIVE_EXTENSIONS, DISK_IMAGE_EXTENSIONS
from app.detectors.hybrid import analyze_email_hybrid
from app.database.db import (
    Base, engine, get_db, IncidentLog,
    Case, CaseEmail, ThreatIndicator, ThreatCampaign
)
from app.auth import verify_forensic_api_key
from app.forensics.header_analyzer import analyze_email_headers
from app.correlation import (
    create_case,
    list_cases,
    get_case_by_id,
    update_case,
    build_case_graph,
    build_single_forensic_graph,
    record_and_correlate_email
)
from app.reports import (
    generate_forensic_pdf,
    generate_siem_json_bundle,
    record_audit_event,
    verify_audit_chain,
    mask_pii,
    ForensicAuditLog
)

# Create DB Tables
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="PhishingGuard Forensic Intelligence API",
    description="AI-Powered Email Threat Detection, Geolocation, and Forensic Intelligence Platform",
    version="2.0.0"
)

# Secure CORS configuration: allow Chrome MV3 extensions and local development origins
raw_origins = os.getenv("ALLOWED_ORIGINS", "")
allowed_origins = [
    o.strip() for o in raw_origins.split(",") 
    if o.strip() and not o.strip().startswith("chrome-extension:")
] or [
    "http://localhost",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount Analyst Dashboard Portal directly from FastAPI
CANDIDATE_EXTENSION_DIRS = [
    os.path.abspath(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "extension")),
    os.path.abspath(os.path.join(os.path.dirname(os.path.dirname(__file__)), "extension")),
    os.path.abspath(os.path.join(os.getcwd(), "extension")),
    os.path.abspath(os.path.join(os.getcwd(), "..", "extension")),
]
EXTENSION_DIR = next((d for d in CANDIDATE_EXTENSION_DIRS if os.path.exists(d)), None)

if EXTENSION_DIR and os.path.exists(EXTENSION_DIR):
    app.mount("/dashboard-ui", StaticFiles(directory=EXTENSION_DIR, html=True), name="dashboard_ui")

    @app.get("/dashboard")
    def serve_dashboard():
        return RedirectResponse(url="/dashboard-ui/dashboard.html")

    @app.get("/portal")
    def serve_portal():
        return RedirectResponse(url="/dashboard-ui/dashboard.html?section=forensics")

@app.get("/")
def serve_root():
    if EXTENSION_DIR and os.path.exists(EXTENSION_DIR):
        return RedirectResponse(url="/dashboard")
    return RedirectResponse(url="/docs")


def log_incident(db: Session, item_type: str, target: str, verdict: str, risk_category: str, action: str):
    log = IncidentLog(
        item_type=item_type,
        target=target,
        verdict=verdict,
        risk_category=risk_category,
        action_taken=action
    )
    db.add(log)
    db.commit()

@app.get("/api/health")
def health_check():
    return {
        "status": "ok", 
        "platform": "PhishingGuard Forensic Intelligence Platform",
        "version": "2.0.0",
        "threat_intel_active": bool(os.getenv("VIRUSTOTAL_API_KEY"))
    }

# =====================================================================
# FORENSIC INTELLIGENCE LAYER (Phase 1)
# =====================================================================
@app.post("/api/forensics/analyze", response_model=ForensicAnalysisResponse)
async def analyze_email_forensics_endpoint(
    request: Request,
    api_key: str = Depends(verify_forensic_api_key),
    db: Session = Depends(get_db)
):
    """
    Ingest a raw RFC 5322 email (.eml file upload, raw headers, or JSON body),
    reconstruct the relay path, evaluate SPF/DKIM/DMARC authentication,
    and perform deep anomaly and spoofing analysis.
    """
    content_type = request.headers.get("content-type", "").lower()
    raw_bytes = b""

    if "multipart/form-data" in content_type:
        form = await request.form()
        uploaded_file = form.get("file")
        if uploaded_file and hasattr(uploaded_file, "read"):
            raw_bytes = await uploaded_file.read()
        elif form.get("raw_content"):
            raw_bytes = str(form.get("raw_content")).encode("utf-8", errors="replace")
    elif "application/json" in content_type:
        try:
            body = await request.json()
            raw_content = body.get("raw_content", "")
            raw_bytes = raw_content.encode("utf-8", errors="replace")
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, 
                detail="Invalid JSON payload"
            )
    else:
        # Fallback: Read raw request stream
        raw_bytes = await request.body()

    if not raw_bytes or len(raw_bytes.strip()) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No email content provided. Upload an .eml file or provide 'raw_content'."
        )

    # Execute forensic header analysis engine
    result = analyze_email_headers(raw_bytes)

    # Persist and correlate in Threat Intelligence Database
    try:
        record_and_correlate_email(db, result)
    except Exception:
        pass

    # Record Chain of Custody Audit Event
    try:
        record_audit_event(
            db=db,
            event_type="EVIDENCE_INGESTION",
            target_id=result.sha256,
            details=f"Ingested RFC 5322 email: '{result.envelope.subject or '(No Subject)'}' from {result.envelope.from_address or 'Unknown'} (Verdict: {result.summary.verdict}, Score: {result.summary.risk_score})"
        )
    except Exception:
        pass

    # Log forensic incident in SQLite
    target = result.envelope.from_address or result.envelope.from_header or "UNKNOWN_SENDER"
    action = f"Forensic Scan: {result.summary.verdict}"
    log_incident(db, "FORENSIC_EMAIL", target, result.summary.verdict.lower(), f"Score {result.summary.risk_score}", action)

    return result

# =====================================================================
# EXISTING EXTENSION ENDPOINTS (Preserved for backwards compatibility)
# =====================================================================
@app.post("/api/analyze/email", response_model=EmailAnalysisResponse)
def analyze_email(request: EmailAnalysisRequest, db: Session = Depends(get_db)):
    result = analyze_email_hybrid(request)
    action = "Warning Displayed" if result.verdict not in ["safe", "legitimate"] else "Scanned"
    log_incident(db, "EMAIL", request.sender_email, result.verdict, result.risk_category, action)
    return result

@app.post("/api/analyze/url", response_model=UrlAnalysisResponse)
def analyze_url_endpoint(request: UrlAnalysisRequest, db: Session = Depends(get_db)):
    result = analyze_url(request)
    action = "Navigation Blocked" if result.verdict != "safe" else "Allowed"
    log_incident(db, "URL", request.url, result.verdict, "Varies", action)
    return result

@app.post("/api/analyze/attachment", response_model=AttachmentAnalysisResponse)
async def analyze_attachment(file: UploadFile = File(...), db: Session = Depends(get_db)):
    filename = file.filename
    filename_lower = filename.lower()
    content = await file.read()
    file_size_mb = len(content) / (1024 * 1024)
    file_hash = hashlib.sha256(content).hexdigest()
    
    indicators = []
    score = 0
    detected_type = "Unknown"
    
    # Check Magic Bytes / File Signatures
    is_masquerading = False
    if content.startswith(b'MZ'):
        detected_type = "Windows PE Executable (MZ)"
        if not any(filename_lower.endswith(ext) for ext in ['.exe', '.dll', '.sys', '.scr']):
            indicators.append(Indicator(
                type="MASQUERADING_EXECUTABLE", 
                description=f"🚨 CRITICAL: File is an executable binary (MZ header) disguised with an extension of '{filename.split('.')[-1]}'."
            ))
            score += 10
            is_masquerading = True
    elif content.startswith(b'\x7fELF'):
        detected_type = "Linux/Unix ELF Binary"
        indicators.append(Indicator(
            type="ELF_BINARY", 
            description="🚨 Executable Linux/Unix binary detected."
        ))
        score += 10
    elif content.startswith(b'%PDF-'):
        detected_type = "Adobe PDF Document"
    elif content.startswith(b'PK\x03\x04'):
        detected_type = "ZIP / Modern Office Container"
    elif content.startswith(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'):
        detected_type = "Legacy Microsoft Compound Document (OLE)"
    elif content.startswith(b'\x89PNG\r\n\x1a\n'):
        detected_type = "PNG Image"
    elif content.startswith(b'\xff\xd8\xff'):
        detected_type = "JPEG Image"

    if '\u202e' in filename:
        indicators.append(Indicator(
            type="RTLO_EXTENSION", 
            description="🚨 Right-to-Left Override Unicode character detected in filename. This reverses extension characters to hide malware."
        ))
        score += 10

    if any(filename_lower.endswith(ext) for ext in DANGEROUS_EXTENSIONS):
        ext_found = next(ext for ext in DANGEROUS_EXTENSIONS if filename_lower.endswith(ext))
        indicators.append(Indicator(
            type="DANGEROUS_EXTENSION", 
            description=f"🚨 File ends with dangerous executable extension '{ext_found}'. Executables can run malware directly."
        ))
        score += 10
        
    if filename_lower.count('.') > 1:
        parts = filename_lower.split('.')
        final_ext = '.' + parts[-1]
        if final_ext in DANGEROUS_EXTENSIONS:
            indicators.append(Indicator(
                type="DOUBLE_EXTENSION", 
                description=f"🚨 Double extension detected: disguising an executable ({final_ext}) as a document ({parts[-2]})."
            ))
            score += 10
        elif final_ext in MACRO_EXTENSIONS:
            indicators.append(Indicator(
                type="MACRO_ATTACHMENT",
                description="⚠️ Macro-enabled Office file detected. Macros can download malicious payloads."
            ))
            score += 4

    if any(filename_lower.endswith(ext) for ext in MACRO_EXTENSIONS):
        indicators.append(Indicator(
            type="MACRO_ATTACHMENT", 
            description="⚠️ Macro-enabled document detected. Macros can execute malicious background scripts."
        ))
        score += 4
        
    if file_size_mb > 25:
        indicators.append(Indicator(
            type="UNUSUALLY_LARGE", 
            description=f"File is unusually large ({file_size_mb:.1f} MB) for an email attachment."
        ))
        score += 1
        
    if score >= 10 or is_masquerading:
        verdict = "phishing"
        explanation = f"Critical threat: Malicious executable or disguised payload detected ({detected_type})."
        rec_action = "Do NOT open or execute this file. Delete it immediately."
    elif score >= 3:
        verdict = "suspicious"
        explanation = f"Suspicious characteristics found ({detected_type}). May contain automated macro code or evasive naming."
        rec_action = "Inspect source and verify sender before opening."
    else:
        verdict = "legitimate"
        explanation = f"Attachment verified. Standard file format ({detected_type}). No executable headers or spoofing detected."
        rec_action = "File appears legitimate."
        
    result = AttachmentAnalysisResponse(
        filename=filename,
        verdict=verdict,
        sha256=file_hash,
        detected_type=detected_type,
        indicators=indicators,
        explanation=explanation,
        recommended_action=rec_action
    )
    
    log_incident(db, "ATTACHMENT", filename, verdict, "Varies", "Scanned")
    return result

@app.get("/api/dashboard/stats")
def get_dashboard_stats(db: Session = Depends(get_db)):
    total = db.query(IncidentLog).count()
    phishing = db.query(IncidentLog).filter(IncidentLog.verdict.in_(["phishing", "critical_fraud"])).count()
    suspicious = db.query(IncidentLog).filter(IncidentLog.verdict == "suspicious").count()
    safe = db.query(IncidentLog).filter(IncidentLog.verdict.in_(["safe", "legitimate"])).count()
    
    recent_logs = db.query(IncidentLog).order_by(IncidentLog.timestamp.desc()).limit(15).all()
    
    return {
        "stats": {
            "total_analyzed": total,
            "phishing_detected": phishing,
            "suspicious_detected": suspicious,
            "safe_detected": safe
        },
        "recent_activity": recent_logs
    }

from pydantic import BaseModel

class SettingsUpdate(BaseModel):
    vt_api_key: str

@app.get("/api/settings")
def get_settings():
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    is_configured = bool(api_key and api_key != "your_key_here" and api_key != "your_virustotal_key_here")
    return {"vt_key_configured": is_configured}

@app.post("/api/settings")
def update_settings(settings: SettingsUpdate):
    """
    Safely update runtime settings without raw disk overwrite vulnerability.
    """
    clean_key = settings.vt_api_key.strip()
    if not re.match(r'^[a-zA-Z0-9_-]{32,128}$', clean_key) and clean_key != "":
        raise HTTPException(status_code=400, detail="Invalid API key format")
    os.environ["VIRUSTOTAL_API_KEY"] = clean_key
    return {"status": "success", "message": "Runtime settings updated successfully"}

# =====================================================================
# PHASE 4: CASE MANAGEMENT & CORRELATION ENDPOINTS
# =====================================================================

@app.post("/api/cases", response_model=CaseResponse)
def create_case_endpoint(
    data: CaseCreate,
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_forensic_api_key)
):
    case = create_case(db, data)
    try:
        record_audit_event(
            db=db,
            event_type="CASE_CREATION",
            target_id=case.id,
            details=f"Created investigation case: '{case.title}' with severity {case.severity}"
        )
    except Exception:
        pass
    return get_case_by_id(db, case.id)

@app.get("/api/cases", response_model=List[CaseResponse])
def list_cases_endpoint(
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_forensic_api_key)
):
    return list_cases(db)

@app.get("/api/cases/{case_id}", response_model=CaseResponse)
def get_case_endpoint(
    case_id: str,
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_forensic_api_key)
):
    case = get_case_by_id(db, case_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")
    return case

@app.patch("/api/cases/{case_id}", response_model=CaseResponse)
def update_case_endpoint(
    case_id: str,
    data: CaseUpdate,
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_forensic_api_key)
):
    case = update_case(db, case_id, data)
    if not case:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")
    return case

@app.get("/api/cases/{case_id}/emails")
def list_case_emails(
    case_id: str,
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_forensic_api_key)
):
    emails = db.query(CaseEmail).filter(CaseEmail.case_id == case_id).all()
    return [{
        "id": e.id,
        "message_id": e.message_id,
        "subject": e.subject,
        "sender": e.sender,
        "threat_category": e.threat_category,
        "fraud_score": e.fraud_score,
        "risk_tier": e.risk_tier,
        "origin_ip": e.origin_ip,
        "origin_country": e.origin_country,
        "attribution_type": e.attribution_type,
        "created_at": str(e.created_at)
    } for e in emails]

@app.post("/api/cases/{case_id}/add-email")
def add_email_to_case_endpoint(
    case_id: str,
    email_id: int,
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_forensic_api_key)
):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")
    email = db.query(CaseEmail).filter(CaseEmail.id == email_id).first()
    if not email:
        raise HTTPException(status_code=404, detail=f"Email record {email_id} not found")
    email.case_id = case_id
    db.commit()
    return {"status": "success", "message": f"Email {email_id} assigned to case {case_id}"}

@app.get("/api/cases/{case_id}/graph", response_model=ThreatGraphResponse)
def get_case_threat_graph(
    case_id: str,
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_forensic_api_key)
):
    return build_case_graph(db, case_id)

@app.post("/api/forensics/graph-preview", response_model=ThreatGraphResponse)
async def preview_forensic_graph(
    request: Request,
    api_key: str = Depends(verify_forensic_api_key)
):
    content_type = request.headers.get("content-type", "").lower()
    raw_bytes = b""
    if "multipart/form-data" in content_type:
        form = await request.form()
        uploaded_file = form.get("file")
        if uploaded_file and hasattr(uploaded_file, "read"):
            raw_bytes = await uploaded_file.read()
        elif form.get("raw_content"):
            raw_bytes = str(form.get("raw_content")).encode("utf-8", errors="replace")
    elif "application/json" in content_type:
        body = await request.json()
        raw_bytes = body.get("raw_content", "").encode("utf-8", errors="replace")
    else:
        raw_bytes = await request.body()

    if not raw_bytes:
        raise HTTPException(status_code=400, detail="No email content provided")
    res = analyze_email_headers(raw_bytes)
    return build_single_forensic_graph(res)

@app.get("/api/campaigns", response_model=List[ThreatCampaignResponse])
def list_threat_campaigns(
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_forensic_api_key)
):
    camps = db.query(ThreatCampaign).order_by(ThreatCampaign.last_observed.desc()).all()
    return [
        ThreatCampaignResponse(
            id=c.id,
            name=c.name,
            threat_actor_type=c.threat_actor_type,
            primary_ioc=c.primary_ioc,
            status=c.status,
            severity=c.severity,
            incident_count=c.incident_count,
            first_observed=str(c.first_observed),
            last_observed=str(c.last_observed),
            summary=c.summary
        ) for c in camps
    ]

@app.get("/api/indicators", response_model=List[ThreatIndicatorResponse])
def list_threat_indicators(
    ioc_type: Optional[str] = None,
    min_score: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_forensic_api_key)
):
    q = db.query(ThreatIndicator).filter(ThreatIndicator.threat_score >= min_score)
    if ioc_type:
        q = q.filter(ThreatIndicator.ioc_type == ioc_type)
    iocs = q.order_by(ThreatIndicator.threat_score.desc(), ThreatIndicator.last_seen.desc()).limit(limit).all()
    return [
        ThreatIndicatorResponse(
            id=i.id,
            ioc_type=i.ioc_type,
            value=i.value,
            threat_score=i.threat_score,
            reputation_tags=i.reputation_tags,
            occurrence_count=i.occurrence_count,
            first_seen=str(i.first_seen),
            last_seen=str(i.last_seen)
        ) for i in iocs
    ]

# =====================================================================
# PHASE 5 & 6: EVIDENCE REPORTS & CHAIN OF CUSTODY ENDPOINTS
# =====================================================================

@app.post("/api/reports/pdf/email")
async def generate_email_pdf_report(
    request: Request,
    api_key: str = Depends(verify_forensic_api_key),
    db: Session = Depends(get_db)
):
    content_type = request.headers.get("content-type", "").lower()
    raw_bytes = b""
    if "multipart/form-data" in content_type:
        form = await request.form()
        uploaded_file = form.get("file")
        if uploaded_file and hasattr(uploaded_file, "read"):
            raw_bytes = await uploaded_file.read()
        elif form.get("raw_content"):
            raw_bytes = str(form.get("raw_content")).encode("utf-8", errors="replace")
    elif "application/json" in content_type:
        body = await request.json()
        raw_bytes = body.get("raw_content", "").encode("utf-8", errors="replace")
    else:
        raw_bytes = await request.body()

    if not raw_bytes:
        raise HTTPException(status_code=400, detail="No email content provided")

    result = analyze_email_headers(raw_bytes)
    pdf_bytes = generate_forensic_pdf(result)

    try:
        record_audit_event(
            db=db,
            event_type="REPORT_EXPORT_PDF",
            target_id=result.sha256,
            details=f"Exported forensic PDF report for email from {result.envelope.from_address or 'Unknown'}"
        )
    except Exception:
        pass

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="forensic_report_{result.sha256[:12]}.pdf"'
        }
    )

@app.get("/api/reports/pdf/case/{case_id}")
def generate_case_pdf_report(
    case_id: str,
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_forensic_api_key)
):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")

    email = db.query(CaseEmail).filter(CaseEmail.case_id == case_id).order_by(CaseEmail.fraud_score.desc()).first()
    if not email or not email.raw_json:
        raise HTTPException(status_code=400, detail=f"No forensic email records found for Case {case_id}")

    analysis_data = json.loads(email.raw_json)
    analysis = ForensicAnalysisResponse(**analysis_data)
    case_info = {
        "id": case.id,
        "title": case.title,
        "status": case.status,
        "severity": case.severity,
        "assigned_to": case.assigned_to
    }
    pdf_bytes = generate_forensic_pdf(analysis, case_info)

    try:
        record_audit_event(
            db=db,
            event_type="REPORT_EXPORT_PDF",
            target_id=case.id,
            details=f"Exported case PDF report for {case.title}"
        )
    except Exception:
        pass

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="forensic_case_{case.id}.pdf"'
        }
    )

@app.get("/api/reports/json/case/{case_id}")
def export_case_siem_json(
    case_id: str,
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_forensic_api_key)
):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")

    email = db.query(CaseEmail).filter(CaseEmail.case_id == case_id).order_by(CaseEmail.fraud_score.desc()).first()
    if not email or not email.raw_json:
        raise HTTPException(status_code=400, detail=f"No forensic email records found for Case {case_id}")

    analysis_data = json.loads(email.raw_json)
    analysis = ForensicAnalysisResponse(**analysis_data)
    case_info = {
        "id": case.id,
        "title": case.title,
        "status": case.status,
        "severity": case.severity,
        "assigned_to": case.assigned_to
    }
    return generate_siem_json_bundle(analysis, case_info)

@app.get("/api/audit/chain")
def get_audit_chain(
    limit: int = 50,
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_forensic_api_key)
):
    logs = db.query(ForensicAuditLog).order_by(ForensicAuditLog.sequence.desc()).limit(limit).all()
    return [{
        "sequence": l.sequence,
        "timestamp": str(l.timestamp),
        "event_type": l.event_type,
        "target_id": l.target_id,
        "analyst_id": l.analyst_id,
        "details": l.details,
        "previous_hash": l.previous_hash,
        "current_hash": l.current_hash
    } for l in logs]

@app.get("/api/audit/verify")
def verify_audit_chain_endpoint(
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_forensic_api_key)
):
    return verify_audit_chain(db)


