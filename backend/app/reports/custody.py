"""
PhishingGuard Chain of Custody & Privacy Compliance Module
Implements tamper-evident append-only SHA-256 cryptographic hash-chained audit logging,
PII redaction, and forensic evidence integrity verification adhering to ISO/IEC 27037 standards.
"""

import hashlib
import re
from datetime import datetime
from typing import Dict, Any, List, Optional
from sqlalchemy import Column, Integer, String, Text, DateTime
from sqlalchemy.orm import Session
from app.database.db import Base

class ForensicAuditLog(Base):
    __tablename__ = "forensic_audit_chain"

    id = Column(Integer, primary_key=True, index=True)
    sequence = Column(Integer, unique=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    event_type = Column(String, index=True)  # EVIDENCE_INGESTION, CASE_CREATION, STATUS_CHANGE, REPORT_EXPORT
    target_id = Column(String, index=True)   # Evidence SHA-256 or Case ID
    analyst_id = Column(String, default="SYSTEM_ANALYSIS_ENGINE")
    details = Column(Text, nullable=True)
    previous_hash = Column(String, nullable=False)
    current_hash = Column(String, nullable=False, unique=True)

GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"

def record_audit_event(
    db: Session,
    event_type: str,
    target_id: str,
    details: str = "",
    analyst_id: str = "SOC_ANALYST"
) -> ForensicAuditLog:
    """
    Appends a new audit record to the cryptographic hash chain.
    Every row contains previous_hash pointing to the previous entry's current_hash.
    """
    # Fetch latest entry in chain
    latest = db.query(ForensicAuditLog).order_by(ForensicAuditLog.sequence.desc()).first()
    
    if not latest:
        next_seq = 1
        prev_hash = GENESIS_HASH
    else:
        next_seq = latest.sequence + 1
        prev_hash = latest.current_hash

    ts = datetime.utcnow()
    # Compute SHA-256 over: sequence + timestamp + event_type + target_id + analyst_id + details + previous_hash
    hash_payload = f"{next_seq}|{ts.isoformat()}|{event_type}|{target_id}|{analyst_id}|{details}|{prev_hash}"
    current_hash = hashlib.sha256(hash_payload.encode("utf-8")).hexdigest()

    log_entry = ForensicAuditLog(
        sequence=next_seq,
        timestamp=ts,
        event_type=event_type,
        target_id=target_id,
        analyst_id=analyst_id,
        details=details,
        previous_hash=prev_hash,
        current_hash=current_hash
    )
    db.add(log_entry)
    db.commit()
    db.refresh(log_entry)
    return log_entry

def verify_audit_chain(db: Session) -> Dict[str, Any]:
    """
    Validates the cryptographic integrity of the entire audit chain.
    Returns validation status, total entries, and any detected tampering.
    """
    entries = db.query(ForensicAuditLog).order_by(ForensicAuditLog.sequence.asc()).all()
    if not entries:
        return {
            "status": "VALID",
            "verified": True,
            "total_records": 0,
            "message": "Audit chain is empty. Genesis state intact."
        }

    expected_prev = GENESIS_HASH
    for e in entries:
        # 1. Verify link to previous
        if e.previous_hash != expected_prev:
            return {
                "status": "TAMPERED",
                "verified": False,
                "broken_at_sequence": e.sequence,
                "error": f"Previous hash mismatch at record #{e.sequence}. Expected {expected_prev}, found {e.previous_hash}."
            }

        # 2. Recompute current hash
        hash_payload = f"{e.sequence}|{e.timestamp.isoformat()}|{e.event_type}|{e.target_id}|{e.analyst_id}|{e.details or ''}|{e.previous_hash}"
        recalculated = hashlib.sha256(hash_payload.encode("utf-8")).hexdigest()
        if recalculated != e.current_hash:
            return {
                "status": "TAMPERED",
                "verified": False,
                "broken_at_sequence": e.sequence,
                "error": f"Current hash signature tampered at record #{e.sequence}."
            }

        expected_prev = e.current_hash

    return {
        "status": "VALID",
        "verified": True,
        "total_records": len(entries),
        "latest_hash": expected_prev,
        "message": f"Cryptographic integrity verified across {len(entries)} sequential audit blocks."
    }

# =========================================================================
# PII Masking & Privacy Utilities
# =========================================================================

# Regex patterns for sensitive data
CREDIT_CARD_REGEX = re.compile(r'\b(?:\d[ -]*?){13,16}\b')
IBAN_REGEX = re.compile(r'\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b')
SSN_REGEX = re.compile(r'\b\d{3}-\d{2}-\d{4}\b')
PHONE_REGEX = re.compile(r'\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b')

def mask_pii(text: str) -> str:
    """
    Redacts credit cards, bank accounts, SSNs, and phone numbers from raw strings
    to maintain privacy and compliance during forensic investigations.
    """
    if not text:
        return ""
    
    # Redact Credit Cards (preserve last 4 digits)
    def mask_cc(match):
        digits = re.sub(r'\D', '', match.group(0))
        if 13 <= len(digits) <= 16:
            return f"****-****-****-{digits[-4:]}"
        return match.group(0)

    # Redact IBAN / Bank accounts
    def mask_iban(match):
        val = match.group(0)
        return f"{val[:4]}****************{val[-3:]}"

    redacted = CREDIT_CARD_REGEX.sub(mask_cc, text)
    redacted = IBAN_REGEX.sub(mask_iban, redacted)
    redacted = SSN_REGEX.sub("***-**-****", redacted)
    redacted = PHONE_REGEX.sub("[PHONE_REDACTED]", redacted)
    return redacted
