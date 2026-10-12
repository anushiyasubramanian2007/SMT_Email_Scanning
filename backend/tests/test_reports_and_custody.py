import os
import json
import pytest
from app.forensics.header_analyzer import analyze_email_headers
from app.reports.generator import generate_forensic_pdf, generate_siem_json_bundle
from app.reports.custody import (
    record_audit_event,
    verify_audit_chain,
    mask_pii,
    ForensicAuditLog
)
from app.database.db import get_db, Case, CaseEmail

# =====================================================================
# 1. FORENSIC PDF & SIEM REPORT GENERATION UNIT TESTS
# =====================================================================

def test_generate_forensic_pdf_bytes(load_fixture):
    """Verify ReportLab produces valid binary PDF with standard header."""
    eml = load_fixture("bec_invoice_fraud.eml")
    result = analyze_email_headers(eml)

    case_info = {"id": "CASE-TEST-001", "title": "Operation Red Wire", "status": "OPEN", "severity": "CRITICAL"}
    pdf_bytes = generate_forensic_pdf(result, case_info)

    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 5000
    # Standard PDF magic header check
    assert pdf_bytes.startswith(b"%PDF-")

def test_generate_siem_json_bundle(load_fixture):
    """Verify SIEM/SOAR bundle export contains compliant schemas and metadata."""
    eml = load_fixture("tor_origin.eml")
    result = analyze_email_headers(eml)

    bundle = generate_siem_json_bundle(result, {"id": "CASE-TOR-99", "title": "Tor Origin Probe"})
    assert bundle["schema_version"] == "2.0.0"
    assert "evidence" in bundle
    assert "attribution" in bundle
    assert "authentication" in bundle
    assert "findings" in bundle
    assert bundle["evidence"]["sha256"] == result.sha256
    assert bundle["attribution"]["archetype"] == "ANONYMIZED_INFRASTRUCTURE"

# =====================================================================
# 2. CRYPTOGRAPHIC CHAIN OF CUSTODY INTEGRITY TESTS
# =====================================================================

def test_chain_of_custody_hash_chaining():
    """Verify append-only audit trail cryptographically chains previous blocks."""
    db = next(get_db())

    # Record 3 sequential events
    ev1 = record_audit_event(db, "EVIDENCE_INGESTION", "SHA256_TEST_1", "Ingested test email 1")
    ev2 = record_audit_event(db, "CASE_CREATION", "CASE-TEST-2", "Opened case 2")
    ev3 = record_audit_event(db, "STATUS_CHANGE", "CASE-TEST-2", "Updated status to INVESTIGATING")

    assert ev2.previous_hash == ev1.current_hash
    assert ev3.previous_hash == ev2.current_hash
    assert ev1.sequence < ev2.sequence < ev3.sequence

    # Verify overall chain integrity
    report = verify_audit_chain(db)
    assert report["verified"] is True
    assert report["status"] == "VALID"
    assert report["total_records"] >= 3

def test_chain_of_custody_tamper_detection():
    """Verify audit chain detects if any historical block is modified or forged."""
    db = next(get_db())

    # Get a random entry from the database
    target_entry = db.query(ForensicAuditLog).filter(ForensicAuditLog.sequence > 1).first()
    if target_entry:
        original_details = target_entry.details
        try:
            # Artificially tamper with the entry
            target_entry.details = "TAMPERED_DETAILS_BY_MALICIOUS_ACTOR"
            db.commit()

            # Chain verification must fail immediately
            report = verify_audit_chain(db)
            assert report["verified"] is False
            assert report["status"] == "TAMPERED"
            assert report["broken_at_sequence"] == target_entry.sequence
        finally:
            # Revert tamper so other tests pass cleanly
            target_entry.details = original_details
            db.commit()

# =====================================================================
# 3. PII MASKING TESTS
# =====================================================================

def test_pii_masking_utilities():
    """Verify sensitive PII (credit cards, IBAN, SSN, phone) is redacted properly."""
    raw_text = (
        "Please transfer funds from account US1234567890123456789012 to card 4532-1234-5678-9010. "
        "Tax ID is 123-45-6789 and direct line is 555-019-2834."
    )
    masked = mask_pii(raw_text)

    # Credit card masked with last 4
    assert "9010" in masked
    assert "4532-1234" not in masked
    # SSN masked
    assert "***-**-****" in masked
    assert "123-45-6789" not in masked
    # Phone redacted
    assert "[PHONE_REDACTED]" in masked

# =====================================================================
# 4. REST API REPORT & CUSTODY ENDPOINT TESTS
# =====================================================================

def test_api_report_pdf_email(client, auth_headers, load_fixture):
    """Verify POST /api/reports/pdf/email streams a valid PDF."""
    eml = load_fixture("credential_harvesting.eml")
    resp = client.post(
        "/api/reports/pdf/email",
        files={"file": ("credential_harvesting.eml", eml, "message/rfc822")},
        headers=auth_headers
    )
    assert resp.status_code == 200
    assert resp.headers.get("content-type") == "application/pdf"
    assert resp.content.startswith(b"%PDF-")

def test_api_report_case_pdf_and_json(client, auth_headers, load_fixture):
    """Verify case PDF and SIEM JSON endpoints work end-to-end."""
    eml = load_fixture("bec_invoice_fraud.eml")

    # Ingest email
    ingest_resp = client.post(
        "/api/forensics/analyze",
        files={"file": ("bec.eml", eml, "message/rfc822")},
        headers=auth_headers
    )
    assert ingest_resp.status_code == 200

    # Create Case
    case_resp = client.post(
        "/api/cases",
        json={"title": "Case for PDF Test", "severity": "HIGH"},
        headers=auth_headers
    )
    case_id = case_resp.json()["id"]

    # Link email to case
    db = next(get_db())
    latest_email = db.query(CaseEmail).order_by(CaseEmail.id.desc()).first()
    client.post(f"/api/cases/{case_id}/add-email?email_id={latest_email.id}", headers=auth_headers)

    # 1. Download Case PDF
    pdf_resp = client.get(f"/api/reports/pdf/case/{case_id}", headers=auth_headers)
    assert pdf_resp.status_code == 200
    assert pdf_resp.headers.get("content-type") == "application/pdf"
    assert pdf_resp.content.startswith(b"%PDF-")

    # 2. Download Case SIEM JSON
    json_resp = client.get(f"/api/reports/json/case/{case_id}", headers=auth_headers)
    assert json_resp.status_code == 200
    bundle = json_resp.json()
    assert bundle["schema_version"] == "2.0.0"
    assert bundle["case"]["id"] == case_id

def test_api_audit_chain_and_verify(client, auth_headers):
    """Verify GET /api/audit/chain and GET /api/audit/verify."""
    chain_resp = client.get("/api/audit/chain", headers=auth_headers)
    assert chain_resp.status_code == 200
    chain = chain_resp.json()
    assert len(chain) > 0
    assert "current_hash" in chain[0]

    verify_resp = client.get("/api/audit/verify", headers=auth_headers)
    assert verify_resp.status_code == 200
    report = verify_resp.json()
    assert report["verified"] is True
    assert report["status"] == "VALID"
