"""
PhishingGuard Forensic Intelligence: Origin Attribution Engine
Evaluates provenance signals, cryptographic alignment, and infrastructure indicators
to attribute threat actors to specific operational archetypes (Compromised Account,
Direct Spoofing, Anonymized Infrastructure, or Forged Relay).
"""

from typing import List, Optional, Dict, Any
from app.schemas.forensic_schemas import (
    EmailEnvelope,
    AuthenticationForensics,
    OriginTraceResult,
    DomainIntelResult,
    ForensicFinding,
    FraudScoreBreakdown,
    OriginAttributionResult,
    InfrastructureEvidence
)

def attribute_threat_origin(
    envelope: EmailEnvelope,
    auth: AuthenticationForensics,
    findings: List[ForensicFinding],
    origin_trace: Optional[OriginTraceResult] = None,
    domain_intel: Optional[DomainIntelResult] = None,
    fraud_score: Optional[FraudScoreBreakdown] = None,
    infra_evidence: Optional[InfrastructureEvidence] = None
) -> OriginAttributionResult:
    """
    Classifies the operational attribution archetype with confidence scoring
    and supporting forensic evidence.
    """
    finding_ids = {f.id for f in findings}
    evidence: List[str] = []

    # Check for Tor / Anonymization Network
    is_tor = (
        "TOR_EXIT_NODE_ORIGIN" in finding_ids or 
        (origin_trace and origin_trace.geolocation and origin_trace.geolocation.is_tor)
    )
    is_vpn = (
        "HOSTED_OR_VPN_PROVIDER" in finding_ids or
        (origin_trace and origin_trace.geolocation and origin_trace.geolocation.is_vpn_proxy)
    )

    if is_tor:
        ip = origin_trace.origin_ip if origin_trace else "Unknown"
        evidence.append(f"Origin IP ({ip}) verified against directory of active Tor exit nodes.")
        if origin_trace and origin_trace.geolocation:
            evidence.append(f"Node routed through network operator: {origin_trace.geolocation.isp or 'Tor Router'}.")
        return OriginAttributionResult(
            archetype="ANONYMIZED_INFRASTRUCTURE",
            confidence=0.96,
            title="Anonymized Adversary Infrastructure (Tor Relay Network)",
            explanation=(
                f"Threat actor intentionally routed malicious traffic through Tor exit node {ip} "
                "to obscure their physical geography and ISP jurisdiction."
            ),
            evidence=evidence
        )

    # Check for Account Takeover (ATO) / Compromised Account
    # Key characteristic of ATO: SPF/DMARC not failing (sent via legitimate corporate infra),
    # but Reply-To is diverted to an external personal inbox, or severe wire fraud / BEC text is present.
    auth_not_failing = (
        auth.spf.verdict not in ["fail"] and 
        auth.dmarc.verdict not in ["fail"]
    )
    has_reply_to_diversion = "REPLY_TO_DIVERSION" in finding_ids
    is_bec = (fraud_score and fraud_score.predicted_category == "bec_fraud") or has_reply_to_diversion

    if auth_not_failing and (has_reply_to_diversion or is_bec):
        evidence.append(f"Cryptographic authentication (SPF: {auth.spf.verdict}, DMARC: {auth.dmarc.verdict}) verified legitimate sender domain.")
        if has_reply_to_diversion:
            evidence.append(f"Header Reply-To ({envelope.reply_to}) diverts replies to external consumer mailbox.")
        evidence.append("Linguistic analysis detected targeted wire transfer or financial coercion.")
        return OriginAttributionResult(
            archetype="COMPROMISED_ACCOUNT",
            confidence=0.92,
            title="Compromised Corporate Identity / Account Takeover (ATO)",
            explanation=(
                f"The email was dispatched through authentic {envelope.from_domain} mail infrastructure with valid "
                "cryptographic signatures, but the Reply-To communication diversion confirms the authorized "
                "account credentials or session tokens have been hijacked by a threat actor (BEC CEO Fraud)."
            ),
            evidence=evidence
        )

    # Check for Lookalike / Direct Spoofing
    is_lookalike = (
        "LOOKALIKE_BRAND_DOMAIN" in finding_ids or 
        (domain_intel and domain_intel.is_lookalike)
    )
    is_display_spoofing = "DISPLAY_NAME_EMAIL_SPOOFING" in finding_ids or "BRAND_IMPERSONATION_DISPLAY_NAME" in finding_ids
    is_auth_fail = auth.spf.verdict == "fail" or auth.dmarc.verdict == "fail" or auth.dkim.aligned is False

    if is_lookalike:
        target = domain_intel.lookalike_target if domain_intel else "legitimate brand"
        evidence.append(f"Domain '{envelope.from_domain}' is a visual homoglyph / typosquat of target '{target}'.")
        if domain_intel and domain_intel.is_newly_registered:
            evidence.append(f"Lookalike domain is newly registered ({domain_intel.domain_age_days} days old).")
        return OriginAttributionResult(
            archetype="SPOOFED_IDENTITY",
            confidence=0.95,
            title=f"Lookalike Typosquatting Domain Campaign (Targeting {target})",
            explanation=(
                f"Adversary registered a deceptive homoglyph domain ({envelope.from_domain}) imitating "
                f"{target} to bypass visual inspection and deceive recipients."
            ),
            evidence=evidence
        )

    if is_display_spoofing:
        evidence.append(f"Display name masquerades as target while actual envelope is '{envelope.from_address}'.")
        return OriginAttributionResult(
            archetype="SPOOFED_IDENTITY",
            confidence=0.93,
            title="Display-Name Impersonation Spoofing",
            explanation=(
                f"Attacker manipulated display headers ({envelope.from_display_name}) to impersonate an executive "
                f"or brand, while delivering from an unrelated address ({envelope.from_address})."
            ),
            evidence=evidence
        )

    if is_auth_fail and (auth.spf.verdict == "fail" or auth.dmarc.verdict == "fail"):
        evidence.append(f"Sender IP unauthorized by {envelope.from_domain} SPF/DMARC policy.")
        if origin_trace and origin_trace.origin_ip:
            evidence.append(f"Unauthorized dispatch origin IP: {origin_trace.origin_ip}.")
        return OriginAttributionResult(
            archetype="SPOOFED_IDENTITY",
            confidence=0.90,
            title="Unauthorized Direct Domain Spoofing",
            explanation=(
                f"Origin mail server attempted to send email forged as {envelope.from_domain} without valid "
                "cryptographic alignment, failing DMARC enforcement."
            ),
            evidence=evidence
        )

    # Check for Forged Relays / Transport Manipulation
    if "RECEIVED_CHAIN_TIME_INVERSION" in finding_ids:
        evidence.append("Anomalous negative timestamp delta detected across consecutive transmission hops.")
        return OriginAttributionResult(
            archetype="UNAUTHENTICATED_RELAY",
            confidence=0.88,
            title="Forged Hop / Tampered Header Provenance",
            explanation=(
                "Chronological time inversions detected in Received headers confirm headers were artificially "
                "synthesized or injected to fabricate a legitimate delivery history."
            ),
            evidence=evidence
        )

    if is_vpn:
        evidence.append(f"Origin IP ({origin_trace.origin_ip}) hosted on commercial proxy/hosting provider.")
        return OriginAttributionResult(
            archetype="ANONYMIZED_INFRASTRUCTURE",
            confidence=0.84,
            title="Commercial VPN / Datacenter Relay Infrastructure",
            explanation=(
                "Transmission originated from commercial hosting or proxy IP space rather than typical "
                "enterprise mail exchange relays."
            ),
            evidence=evidence
        )

    # Check for Provider Relay (Google, Microsoft, Amazon, etc. where real sender IP is scrubbed)
    if origin_trace and origin_trace.origin_status == "PROVIDER_RELAY":
        p_name = origin_trace.provider_name or "Cloud Mail Provider"
        evidence.append(f"Dispatched via {p_name} shared cloud mail relay infrastructure.")
        evidence.append(f"{p_name} infrastructure scrubs the sender's real IP address from transmission headers.")

        if infra_evidence:
            for link in infra_evidence.links:
                if link.is_suspicious_hosting:
                    evidence.append(f"Corroborating link infrastructure: {link.domain} resolves to {link.resolved_ip} ({link.hosting_provider} - ASN {link.asn}).")
                if link.is_shortener:
                    evidence.append(f"Corroborating link obfuscation: shortened URL redirects to {link.expanded_url or 'external target'}.")
            if infra_evidence.reply_to and infra_evidence.reply_to.is_mismatch:
                evidence.append(f"Corroborating Reply-To divergence: replies directed to {infra_evidence.reply_to.reply_to_address}.")
            if infra_evidence.sender_whois and infra_evidence.sender_whois.is_newly_registered:
                evidence.append(f"Corroborating domain age: {envelope.from_domain} created {infra_evidence.sender_whois.creation_date} ({infra_evidence.sender_whois.domain_age_days}d old).")
        
        is_clean_auth = (auth.spf.verdict in ["pass"] or auth.dkim.verdict in ["pass"])
        if is_clean_auth and (not fraud_score or fraud_score.overall_score < 30):
            evidence.append(f"Cryptographic authentication (SPF/DKIM) verified legitimate delegation for {envelope.from_domain}.")
            return OriginAttributionResult(
                archetype="PROVIDER_RELAY",
                confidence=0.40,  # Strictly capped at 40% for provider relays
                title=f"Cloud Provider Delivery Relay ({p_name})",
                explanation=(
                    f"Message was transmitted via {p_name} infrastructure with valid cryptographic authentication. "
                    "The provider's privacy architecture conceals the original sender's physical client IP. "
                    "Origin cannot be determined from headers."
                ),
                evidence=evidence
            )
        else:
            evidence.append(f"Unauthenticated or abnormal routing through {p_name} cloud infrastructure.")
            return OriginAttributionResult(
                archetype="PROVIDER_ABUSE",
                confidence=0.40,  # Strictly capped at 40% for provider relays
                title=f"Unauthenticated Cloud Mail Delivery ({p_name})",
                explanation=f"Message was relayed through {p_name} but exhibits authentication anomalies or elevated fraud scores.",
                evidence=evidence
            )

    # Clean / Benign Baseline (Direct Authentic Infrastructure - ONLY for verified ORIGIN_FOUND)
    if fraud_score and fraud_score.overall_score < 30 and origin_trace and origin_trace.origin_status == "ORIGIN_FOUND":
        evidence.append("Cryptographic authentication and domain registration records verified.")
        if origin_trace and origin_trace.geolocation:
            evidence.append(f"Probable origin infrastructure IP ({origin_trace.origin_ip}) corresponds to authorized ISP ({origin_trace.geolocation.isp}).")
        return OriginAttributionResult(
            archetype="BENIGN_ORIGIN",
            confidence=0.92,
            title="Authentic Direct Domain Infrastructure",
            explanation=(
                f"Probable origin infrastructure and domain telemetry confirm legitimate delivery for {envelope.from_domain}."
            ),
            evidence=evidence
        )

    # Generic Suspicious
    evidence.append("Mixed provenance indicators detected.")
    return OriginAttributionResult(
        archetype="SUSPICIOUS_PROVENANCE",
        confidence=0.70,
        title="Unverified / Suspicious External Origin",
        explanation="Originating infrastructure exhibits multiple anomalies that could not be conclusively attributed to a single archetype.",
        evidence=evidence
    )
