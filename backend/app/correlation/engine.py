"""
PhishingGuard Correlation & Threat Intelligence Engine
Extracts indicators of compromise (IOCs), records incident provenance,
correlates attacks across temporal boundaries, discovers multi-stage campaigns,
and manages investigation cases for SOC analysts.
"""

from typing import List, Dict, Optional, Any, Set, Tuple
from datetime import datetime
import json
import uuid
from sqlalchemy.orm import Session
from sqlalchemy import or_

from app.schemas.forensic_schemas import (
    ForensicAnalysisResponse,
    CaseCreate,
    CaseUpdate,
    CaseResponse,
    ThreatIndicatorResponse,
    ThreatCampaignResponse
)
from app.database.db import (
    Case,
    CaseEmail,
    ThreatIndicator,
    ThreatCampaign,
    EmailIndicatorAssociation
)
from app.correlation.attribution import attribute_threat_origin

def extract_indicators_from_analysis(res: ForensicAnalysisResponse) -> List[Dict[str, Any]]:
    """
    Extracts structured IOCs (IPs, Domains, Senders, ASNs, URLs, Hashes)
    from a forensic analysis response.
    """
    iocs: List[Dict[str, Any]] = []
    seen: Set[Tuple[str, str]] = set()

    def add_ioc(ioc_type: str, value: str, score: int, tags: str = "", notes: str = ""):
        key = (ioc_type, value.lower().strip())
        if key not in seen and value.strip():
            seen.add(key)
            iocs.append({
                "type": ioc_type,
                "value": value.strip(),
                "threat_score": score,
                "reputation_tags": tags,
                "notes": notes
            })

    risk_score = res.fraud_score.overall_score if res.fraud_score else res.summary.risk_score

    # 1. Sender & Domain
    if res.envelope.from_address:
        add_ioc("sender", res.envelope.from_address, risk_score, "from_address")
    if res.envelope.from_domain:
        is_lookalike = res.domain_intel.is_lookalike if res.domain_intel else False
        dom_tags = "lookalike_squatting" if is_lookalike else "sender_domain"
        add_ioc("domain", res.envelope.from_domain, 90 if is_lookalike else min(60, risk_score), dom_tags)

    # 2. Reply-To Address
    if res.envelope.reply_to and res.envelope.reply_to.lower() != (res.envelope.from_address or "").lower():
        add_ioc("sender", res.envelope.reply_to, 85, "reply_to_diversion", "Diverted communication target")
        if "@" in res.envelope.reply_to:
            r_dom = res.envelope.reply_to.split("@")[-1].lower()
            add_ioc("domain", r_dom, 75, "reply_to_domain")

    # 3. Origin IP & ASN
    if res.origin_trace and res.origin_trace.origin_ip:
        ip = res.origin_trace.origin_ip
        geo = res.origin_trace.geolocation
        ip_tags = []
        if geo and geo.is_tor:
            ip_tags.append("tor_exit_node")
        if geo and geo.is_vpn_proxy:
            ip_tags.append("vpn_proxy")
        if geo and geo.is_cloud:
            ip_tags.append("cloud_hosting")

        add_ioc("ip", ip, 95 if (geo and geo.is_tor) else risk_score, ",".join(ip_tags))

        if geo and geo.asn:
            add_ioc("asn", geo.asn, 50 if (geo and geo.is_tor) else 20, "routing_asn", geo.org or geo.isp or "")

    # 4. Email Hash
    if res.sha256:
        add_ioc("hash", res.sha256, risk_score, "email_sha256", f"Subject: {res.envelope.subject}")

    # 5. Extract URLs from findings
    for f in res.findings:
        f_details = f.details or ""
        for word in f_details.split():
            if word.startswith("http://") or word.startswith("https://"):
                clean_url = word.rstrip(".,;:)'\"")
                add_ioc("url", clean_url, 90 if f.severity in ["CRITICAL", "HIGH"] else 50, "extracted_link")

    return iocs

def record_and_correlate_email(
    db: Session,
    analysis_res: ForensicAnalysisResponse,
    case_id: Optional[str] = None
) -> Tuple[CaseEmail, List[ThreatIndicator], Optional[ThreatCampaign]]:
    """
    Persists analysis to CaseEmail, indexes all IOCs, performs cross-incident correlation,
    and clusters related attacks into ThreatCampaigns.
    """
    # 1. Attribute Origin if not already set
    if not analysis_res.attribution:
        analysis_res.attribution = attribute_threat_origin(
            envelope=analysis_res.envelope,
            auth=analysis_res.authentication,
            findings=analysis_res.findings,
            origin_trace=analysis_res.origin_trace,
            domain_intel=analysis_res.domain_intel,
            fraud_score=analysis_res.fraud_score
        )

    # 2. Extract IOCs
    iocs_data = extract_indicators_from_analysis(analysis_res)

    # 3. Create or Update ThreatIndicators in DB
    persisted_indicators: List[ThreatIndicator] = []
    for item in iocs_data:
        ioc = db.query(ThreatIndicator).filter(
            ThreatIndicator.ioc_type == item["type"],
            ThreatIndicator.value == item["value"]
        ).first()

        if ioc:
            ioc.occurrence_count += 1
            ioc.last_seen = datetime.utcnow()
            ioc.threat_score = max(ioc.threat_score, item["threat_score"])
            if item["reputation_tags"] and item["reputation_tags"] not in (ioc.reputation_tags or ""):
                ioc.reputation_tags = f"{ioc.reputation_tags},{item['reputation_tags']}".strip(",")
        else:
            ioc = ThreatIndicator(
                ioc_type=item["type"],
                value=item["value"],
                threat_score=item["threat_score"],
                reputation_tags=item["reputation_tags"],
                notes=item["notes"],
                occurrence_count=1,
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow()
            )
            db.add(ioc)
        db.flush()
        persisted_indicators.append(ioc)

    # 4. Check for Campaign Clustering
    # Look for other emails sharing high-priority IOCs (same Origin IP, lookalike domain, or reply-to)
    campaign: Optional[ThreatCampaign] = None
    high_priority_values = [
        ioc.value for ioc in persisted_indicators 
        if ioc.ioc_type in ["ip", "domain", "sender"] and ioc.threat_score >= 60
    ]

    if high_priority_values:
        # Check existing associations
        matching_assoc = (
            db.query(EmailIndicatorAssociation)
            .join(ThreatIndicator, EmailIndicatorAssociation.indicator_id == ThreatIndicator.id)
            .filter(ThreatIndicator.value.in_(high_priority_values))
            .all()
        )

        matched_email_ids = {a.case_email_id for a in matching_assoc}
        if len(matched_email_ids) >= 1:
            # Check if any matched email already belongs to a campaign
            existing_camp_email = (
                db.query(CaseEmail)
                .filter(CaseEmail.id.in_(matched_email_ids), CaseEmail.campaign_id.isnot(None))
                .first()
            )
            if existing_camp_email and existing_camp_email.campaign_id:
                campaign = db.query(ThreatCampaign).filter(ThreatCampaign.id == existing_camp_email.campaign_id).first()
                if campaign:
                    campaign.incident_count += 1
                    campaign.last_observed = datetime.utcnow()

            # Otherwise, form a new campaign if multiple correlated incidents share critical IOC
            if not campaign and len(matched_email_ids) >= 1:
                camp_id = f"CAMP-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
                camp_name = f"Campaign: {analysis_res.attribution.archetype.replace('_', ' ').title()} ({high_priority_values[0]})"
                campaign = ThreatCampaign(
                    id=camp_id,
                    name=camp_name,
                    threat_actor_type=analysis_res.attribution.archetype,
                    primary_ioc=high_priority_values[0],
                    status="ACTIVE",
                    severity="HIGH" if (analysis_res.fraud_score and analysis_res.fraud_score.overall_score >= 50) else "MEDIUM",
                    incident_count=len(matched_email_ids) + 1,
                    first_observed=datetime.utcnow(),
                    last_observed=datetime.utcnow(),
                    summary=f"Automated threat campaign correlation targeting {analysis_res.envelope.to_address or 'corporate recipients'} sharing IOC {high_priority_values[0]}."
                )
                db.add(campaign)
                db.flush()

    # 5. Persist CaseEmail Record
    origin_ip = analysis_res.origin_trace.origin_ip if analysis_res.origin_trace else None
    origin_country = analysis_res.origin_trace.geolocation.country if (analysis_res.origin_trace and analysis_res.origin_trace.geolocation) else None
    category = analysis_res.fraud_score.predicted_category if analysis_res.fraud_score else analysis_res.summary.verdict.lower()
    score = analysis_res.fraud_score.overall_score if analysis_res.fraud_score else analysis_res.summary.risk_score
    risk_tier = analysis_res.fraud_score.risk_tier if analysis_res.fraud_score else "LOW"

    case_email = CaseEmail(
        case_id=case_id,
        message_id=analysis_res.envelope.message_id or analysis_res.sha256[:16],
        subject=analysis_res.envelope.subject,
        sender=analysis_res.envelope.from_address,
        recipient=analysis_res.envelope.to_address,
        threat_category=category,
        fraud_score=score,
        risk_tier=risk_tier,
        origin_ip=origin_ip,
        origin_country=origin_country,
        campaign_id=campaign.id if campaign else None,
        attribution_type=analysis_res.attribution.archetype if analysis_res.attribution else "UNKNOWN",
        raw_json=analysis_res.model_dump_json() if hasattr(analysis_res, "model_dump_json") else json.dumps(analysis_res.dict())
    )
    db.add(case_email)
    db.flush()

    # 6. Record Associations
    for ioc in persisted_indicators:
        assoc = EmailIndicatorAssociation(
            case_email_id=case_email.id,
            indicator_id=ioc.id,
            relationship=ioc.reputation_tags or "ASSOCIATED_WITH"
        )
        db.add(assoc)

    db.commit()
    db.refresh(case_email)
    return case_email, persisted_indicators, campaign

# =========================================================================
# Case Management Operations
# =========================================================================

def create_case(db: Session, data: CaseCreate) -> Case:
    """Generates a new investigation case with unique formatted ID."""
    today_str = datetime.utcnow().strftime("%Y%m%d")
    unique_suffix = uuid.uuid4().hex[:5].upper()
    case_id = f"CASE-{today_str}-{unique_suffix}"

    new_case = Case(
        id=case_id,
        title=data.title,
        status="OPEN",
        severity=data.severity or "MEDIUM",
        description=data.description,
        tags=data.tags,
        assigned_to=data.assigned_to or "SOC Analyst"
    )
    db.add(new_case)
    db.commit()
    db.refresh(new_case)
    return new_case

def list_cases(db: Session) -> List[CaseResponse]:
    """Lists all cases with total email count."""
    cases = db.query(Case).order_by(Case.created_at.desc()).all()
    res: List[CaseResponse] = []
    for c in cases:
        cnt = db.query(CaseEmail).filter(CaseEmail.case_id == c.id).count()
        res.append(CaseResponse(
            id=c.id,
            title=c.title,
            status=c.status,
            severity=c.severity,
            description=c.description,
            tags=c.tags,
            assigned_to=c.assigned_to,
            email_count=cnt,
            created_at=str(c.created_at),
            updated_at=str(c.updated_at)
        ))
    return res

def get_case_by_id(db: Session, case_id: str) -> Optional[CaseResponse]:
    """Retrieves single case metadata."""
    c = db.query(Case).filter(Case.id == case_id).first()
    if not c:
        return None
    cnt = db.query(CaseEmail).filter(CaseEmail.case_id == c.id).count()
    return CaseResponse(
        id=c.id,
        title=c.title,
        status=c.status,
        severity=c.severity,
        description=c.description,
        tags=c.tags,
        assigned_to=c.assigned_to,
        email_count=cnt,
        created_at=str(c.created_at),
        updated_at=str(c.updated_at)
    )

def update_case(db: Session, case_id: str, data: CaseUpdate) -> Optional[CaseResponse]:
    """Updates case status, severity, tags, or assignee."""
    c = db.query(Case).filter(Case.id == case_id).first()
    if not c:
        return None
    if data.title is not None:
        c.title = data.title
    if data.status is not None:
        c.status = data.status
    if data.severity is not None:
        c.severity = data.severity
    if data.description is not None:
        c.description = data.description
    if data.tags is not None:
        c.tags = data.tags
    if data.assigned_to is not None:
        c.assigned_to = data.assigned_to

    c.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(c)
    return get_case_by_id(db, case_id)
