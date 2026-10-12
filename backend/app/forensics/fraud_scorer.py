"""
PhishingGuard Forensics: Multi-Factor Fraud Score Fusion Engine
Fuses NLP linguistic confidence, header transport anomalies, authentication failures,
domain intelligence, and IP infrastructure reputation into a single explainable 0-100 score.
"""

from typing import Dict, List, Optional, Any
from app.schemas.forensic_schemas import (
    FactorScore,
    FraudScoreBreakdown,
    EmailEnvelope,
    AuthenticationForensics,
    OriginTraceResult,
    DomainIntelResult,
    ForensicFinding,
    InfrastructureEvidence
)

def compute_fused_fraud_score(
    nlp_result: Dict[str, Any],
    envelope: EmailEnvelope,
    auth: AuthenticationForensics,
    findings: List[ForensicFinding],
    origin_trace: Optional[OriginTraceResult] = None,
    domain_intel: Optional[DomainIntelResult] = None,
    infra_evidence: Optional[InfrastructureEvidence] = None
) -> FraudScoreBreakdown:
    """
    Computes a 0-100 composite fraud score with transparent per-factor weights
    and an explainable risk breakdown.
    """
    finding_ids = {f.id for f in findings}

    # =========================================================================
    # Factor 1: NLP / Text Linguistic Threat Score (Weight: 25%)
    # =========================================================================
    nlp_cat = nlp_result.get("category", "legitimate")
    nlp_conf = float(nlp_result.get("confidence", 0.0))
    threat_prob = float(nlp_result.get("threat_probability", 0.0))

    if nlp_cat == "bec_fraud":
        nlp_score = min(25.0, 25.0 * nlp_conf)
        nlp_status = "CRITICAL" if nlp_conf >= 0.70 else "WARNING"
        nlp_expl = f"AI NLP Engine flagged Business Email Compromise / wire diversion language ({nlp_conf*100:.1f}% confidence)."
    elif nlp_cat == "phishing":
        nlp_score = min(25.0, 25.0 * nlp_conf)
        nlp_status = "CRITICAL" if nlp_conf >= 0.70 else "WARNING"
        nlp_expl = f"AI NLP Engine detected deceptive credential-theft phishing patterns ({nlp_conf*100:.1f}% confidence)."
    elif nlp_cat == "impersonation":
        nlp_score = min(25.0, 22.0 * nlp_conf)
        nlp_status = "WARNING"
        nlp_expl = f"AI NLP Engine identified brand/executive impersonation language ({nlp_conf*100:.1f}% confidence)."
    elif nlp_cat == "suspicious":
        nlp_score = min(25.0, 16.0 * nlp_conf)
        nlp_status = "WARNING"
        nlp_expl = f"AI NLP Engine flagged promotional urgency or lottery claims ({nlp_conf*100:.1f}% confidence)."
    else:
        nlp_score = max(0.0, min(5.0, 5.0 * (1.0 - nlp_conf)))
        nlp_status = "CLEAN"
        nlp_expl = f"AI NLP Model confirmed benign routine business correspondence ({(1.0 - threat_prob)*100:.1f}% safe)."

    f1 = FactorScore(
        factor_name="NLP Linguistic Threat",
        score=round(nlp_score, 1),
        weight=0.25,
        max_score=25.0,
        status=nlp_status,
        explanation=nlp_expl
    )

    # =========================================================================
    # Factor 2: Header & Transport Anomalies (Weight: 25%)
    # =========================================================================
    hdr_score = 0.0
    hdr_reasons = []

    if "DISPLAY_NAME_EMAIL_SPOOFING" in finding_ids:
        hdr_score += 25.0
        hdr_reasons.append("Critical display name email injection")
    if "REPLY_TO_DIVERSION" in finding_ids:
        bec_finding = next((f for f in findings if f.id == "REPLY_TO_DIVERSION"), None)
        if bec_finding and bec_finding.severity == "CRITICAL":
            hdr_score += 25.0
            hdr_reasons.append("Critical Reply-To freemail diversion (BEC)")
        else:
            hdr_score += 15.0
            hdr_reasons.append("Reply-To communication diversion")
    if "RECEIVED_CHAIN_TIME_INVERSION" in finding_ids:
        hdr_score += 15.0
        hdr_reasons.append("Chronological hop time inversion (forged headers)")
    if "BRAND_IMPERSONATION_DISPLAY_NAME" in finding_ids:
        hdr_score += 12.0
        hdr_reasons.append("Brand display name impersonation")
    if "FROM_RETURN_PATH_MISMATCH" in finding_ids:
        hdr_score += 10.0
        hdr_reasons.append("From vs Return-Path envelope mismatch")
    if "MESSAGE_ID_DOMAIN_MISMATCH" in finding_ids:
        hdr_score += 4.0
        hdr_reasons.append("Message-ID domain discrepancy")
    if "MISSING_MESSAGE_ID" in finding_ids:
        hdr_score += 3.0
        hdr_reasons.append("Missing RFC Message-ID")

    hdr_score = min(25.0, hdr_score)
    hdr_status = "CRITICAL" if hdr_score >= 18.0 else ("WARNING" if hdr_score >= 8.0 else "CLEAN")
    hdr_expl = "; ".join(hdr_reasons) if hdr_reasons else "All email headers and transmission hops align chronologically."

    f2 = FactorScore(
        factor_name="Header & Transport Provenance",
        score=round(hdr_score, 1),
        weight=0.25,
        max_score=25.0,
        status=hdr_status,
        explanation=hdr_expl
    )

    # =========================================================================
    # Factor 3: Cryptographic Authentication (SPF/DKIM/DMARC) (Weight: 20%)
    # =========================================================================
    auth_score = 0.0
    auth_reasons = []

    if auth.dmarc.verdict == "fail" or "DMARC_POLICY_FAILED" in finding_ids:
        auth_score += 20.0
        auth_reasons.append("DMARC alignment failed")
    if auth.spf.verdict == "fail" or "SPF_VERIFICATION_FAILED" in finding_ids:
        auth_score += 15.0
        auth_reasons.append("SPF hard failure (unauthorized IP)")
    elif auth.spf.verdict == "softfail" or "SPF_VERIFICATION_SOFTFAIL" in finding_ids:
        auth_score += 8.0
        auth_reasons.append("SPF softfail warning")
    if auth.dkim.aligned is False or "DKIM_DOMAIN_UNALIGNED" in finding_ids:
        auth_score += 10.0
        auth_reasons.append("DKIM signing domain not aligned with sender")
    elif auth.dkim.verdict == "fail":
        auth_score += 12.0
        auth_reasons.append("DKIM cryptographic signature verification failed")

    auth_score = min(20.0, auth_score)
    auth_status = "CRITICAL" if auth_score >= 15.0 else ("WARNING" if auth_score >= 8.0 else "CLEAN")
    auth_expl = "; ".join(auth_reasons) if auth_reasons else f"Passed cryptographic checks (SPF: {auth.spf.verdict}, DKIM: {auth.dkim.verdict}, DMARC: {auth.dmarc.verdict})."

    f3 = FactorScore(
        factor_name="Cryptographic Authentication",
        score=round(auth_score, 1),
        weight=0.20,
        max_score=20.0,
        status=auth_status,
        explanation=auth_expl
    )

    # =========================================================================
    # Factor 4: Domain Intelligence & Lookalike Risk (Weight: 15%)
    # =========================================================================
    dom_score = 0.0
    dom_reasons = []

    if domain_intel:
        if domain_intel.is_lookalike or "LOOKALIKE_BRAND_DOMAIN" in finding_ids:
            dom_score += 15.0
            dom_reasons.append(f"Lookalike typo-squatting targeting '{domain_intel.lookalike_target}'")
        if domain_intel.is_newly_registered or "NEWLY_REGISTERED_DOMAIN" in finding_ids:
            dom_score += 12.0
            dom_reasons.append(f"Newly registered domain (Age: {domain_intel.domain_age_days}d)")
        elif domain_intel.domain_age_days is not None and domain_intel.domain_age_days < 90:
            dom_score += 6.0
            dom_reasons.append(f"Young domain (Age: {domain_intel.domain_age_days}d)")
        if not domain_intel.has_mx or "DOMAIN_NO_MX_RECORDS" in finding_ids:
            dom_score += 5.0
            dom_reasons.append("Domain has no inbound MX records")
    elif "NEWLY_REGISTERED_DOMAIN" in finding_ids:
        dom_score += 12.0
        age_str = f" (Age: {infra_evidence.sender_whois.domain_age_days}d)" if (infra_evidence and infra_evidence.sender_whois and infra_evidence.sender_whois.domain_age_days is not None) else ""
        dom_reasons.append(f"Newly registered domain{age_str}")

    if "IDN_HOMOGLYPH_LINK" in finding_ids:
        dom_score += 10.0
        dom_reasons.append("IDN homoglyph punycode domain in hyperlink")

    if "URL_SHORTENER_OBSCURATION" in finding_ids:
        dom_score += 5.0
        dom_reasons.append("URL shortener used to obscure destination")

    if "REPLY_TO_DIVERSION" in finding_ids:
        bec_finding = next((f for f in findings if f.id == "REPLY_TO_DIVERSION"), None)
        if bec_finding and bec_finding.severity == "CRITICAL":
            dom_score += 10.0
            dom_reasons.append("External routing risk: Reply-To diverts corporate traffic to consumer webmail")
        else:
            dom_score += 5.0
            dom_reasons.append("External routing risk: Reply-To diverts traffic to external domain")
    elif "REPLY_TO_DOMAIN_MISMATCH" in finding_ids:
        dom_score += 8.0
        dom_reasons.append("External routing risk: Reply-To domain diverges from sender domain")

    dom_score = min(15.0, dom_score)
    dom_status = "CRITICAL" if dom_score >= 12.0 else ("WARNING" if dom_score >= 5.0 else "CLEAN")
    dom_expl = "; ".join(dom_reasons) if dom_reasons else f"Domain '{envelope.from_domain}' shows established history with valid MX."

    f4 = FactorScore(
        factor_name="Domain Intelligence & Lookalike",
        score=round(dom_score, 1),
        weight=0.15,
        max_score=15.0,
        status=dom_status,
        explanation=dom_expl
    )

    # =========================================================================
    # Factor 5: IP Infrastructure & Geo Reputation (Weight: 15%)
    # =========================================================================
    ip_score = 0.0
    ip_reasons = []

    if origin_trace and origin_trace.geolocation:
        geo = origin_trace.geolocation
        if geo.is_tor or "TOR_EXIT_NODE_ORIGIN" in finding_ids:
            ip_score += 15.0
            ip_reasons.append(f"Origin IP ({geo.ip}) is an active TOR exit node")
        elif geo.is_vpn_proxy or "HOSTING_OR_VPN_PROVIDER" in finding_ids:
            ip_score += 10.0
            ip_reasons.append(f"Commercial datacenter / VPN range ({geo.org or geo.isp})")
        elif origin_trace.origin_status == "PROVIDER_RELAY":
            ip_score += 0.0
            ip_reasons.append(f"Sent through {origin_trace.provider_name or 'cloud mail provider'} relay (Client IP scrubbed)")
        elif geo.is_cloud or "CLOUD_INFRASTRUCTURE_ORIGIN" in finding_ids:
            ip_score += 5.0
            ip_reasons.append(f"Cloud provider workload ({geo.isp})")

    if "SUSPICIOUS_LINK_HOSTING" in finding_ids:
        ip_score += 8.0
        ip_reasons.append("Destination links hosted on suspicious/bulletproof cloud provider")

    if "RAW_IP_URL_DESTINATION" in finding_ids:
        ip_score += 6.0
        ip_reasons.append("Destination links use raw numerical IP address")

    ip_score = min(15.0, ip_score)
    ip_status = "CRITICAL" if ip_score >= 15.0 else ("WARNING" if ip_score >= 8.0 else "CLEAN")
    ip_expl = "; ".join(ip_reasons) if ip_reasons else (
        f"Origin IP ({origin_trace.origin_ip}) resolves to regular network in {origin_trace.geolocation.country if origin_trace and origin_trace.geolocation else 'authorized region'}."
    )

    f5 = FactorScore(
        factor_name="IP Infrastructure & Anonymization",
        score=round(ip_score, 1),
        weight=0.15,
        max_score=15.0,
        status=ip_status,
        explanation=ip_expl
    )

    # =========================================================================
    # Total Composite Fraud Score Calculation & Driver Identification
    # =========================================================================
    raw_total = f1.score + f2.score + f3.score + f4.score + f5.score
    total_score = min(100, max(0, int(round(raw_total))))

    # Find dominant risk driver
    factors = [f1, f2, f3, f4, f5]
    factors_sorted = sorted(factors, key=lambda f: f.score / f.max_score, reverse=True)
    top_factor = factors_sorted[0]
    primary_driver = (
        f"{top_factor.factor_name} ({top_factor.score:.0f}/{top_factor.max_score:.0f} pts): {top_factor.explanation}"
        if top_factor.score > 0 else "None (Clean baseline)"
    )

    # Verdict Multi-Class Determination
    has_critical_bec = "REPLY_TO_DIVERSION" in finding_ids and any(f.severity == "CRITICAL" for f in findings if f.id == "REPLY_TO_DIVERSION")

    # Risk Tier Assignment
    if total_score >= 75 or "TOR_EXIT_NODE_ORIGIN" in finding_ids or "DISPLAY_NAME_EMAIL_SPOOFING" in finding_ids:
        risk_tier = "CRITICAL"
    elif total_score >= 50 or has_critical_bec:
        risk_tier = "HIGH"
    elif total_score >= 30:
        risk_tier = "MEDIUM"
    else:
        risk_tier = "LOW"

    if total_score < 30:
        predicted_category = "legitimate"
    elif nlp_cat == "bec_fraud" or has_critical_bec:
        predicted_category = "bec_fraud"
    elif (domain_intel and domain_intel.is_lookalike) or "BRAND_IMPERSONATION_DISPLAY_NAME" in finding_ids or nlp_cat == "impersonation":
        predicted_category = "impersonation"
    elif nlp_cat == "phishing" or "DISPLAY_NAME_EMAIL_SPOOFING" in finding_ids or auth_score >= 12.0:
        predicted_category = "phishing"
    elif nlp_cat in ["bec_fraud", "impersonation", "phishing", "suspicious"]:
        predicted_category = nlp_cat
    else:
        predicted_category = "suspicious"

    return FraudScoreBreakdown(
        overall_score=total_score,
        risk_tier=risk_tier,
        predicted_category=predicted_category,
        primary_risk_driver=primary_driver,
        nlp_linguistic_factor=f1,
        header_transport_factor=f2,
        authentication_factor=f3,
        domain_intel_factor=f4,
        ip_reputation_factor=f5
    )
