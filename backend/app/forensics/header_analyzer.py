"""
PhishingGuard Forensics: Header Analyzer Module
RFC 5322 Email Header Parsing, Authentication Evaluation, and Anomaly Detection.
"""

import email
import email.policy
from email.utils import parseaddr, parsedate_to_datetime
import re
import hashlib
import ipaddress
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Any

from app.schemas.forensic_schemas import (
    ForensicAnalysisResponse,
    ForensicSummary,
    EmailEnvelope,
    AuthenticationForensics,
    AuthStatus,
    RelayHop,
    ForensicFinding,
    InfrastructureEvidence
)

# Known legitimate high-value brands commonly impersonated
HIGH_VALUE_BRANDS = {
    "paypal": ["paypal.com"],
    "microsoft": ["microsoft.com", "office.com", "office365.com", "live.com", "outlook.com"],
    "google": ["google.com", "gmail.com", "googlemail.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.in"],
    "netflix": ["netflix.com"],
    "chase": ["chase.com"],
    "bank of america": ["bankofamerica.com", "bofa.com"],
    "wells fargo": ["wellsfargo.com"],
    "citibank": ["citi.com", "citibank.com"],
    "dhl": ["dhl.com", "dhl.de"],
    "fedex": ["fedex.com"],
    "ups": ["ups.com"],
    "irs": ["irs.gov"],
    "meta": ["meta.com", "facebook.com", "instagram.com"],
    "facebook": ["facebook.com"],
    "instagram": ["instagram.com"],
    "linkedin": ["linkedin.com"],
    "dropbox": ["dropbox.com"]
}

# Free / webmail providers frequently used for BEC diversion
FREEMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "ymail.com", "hotmail.com", "outlook.com",
    "live.com", "aol.com", "icloud.com", "proton.me", "protonmail.com",
    "zoho.com", "mail.com", "gmx.com", "yandex.com", "tutanota.com"
}

IPV4_REGEX = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
IPV6_REGEX = re.compile(r'(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:::|(?:::[0-9a-fA-F]{1,4})+)')

def is_ip_private(ip_str: Optional[str]) -> bool:
    """Check if an IPv4 or IPv6 address is private LAN (RFC 1918), loopback, link-local, reserved, multicast, or cloud internal."""
    if not ip_str:
        return True
    cleaned = ip_str.strip("[]():,; \t\r\n")
    try:
        ip_obj = ipaddress.ip_address(cleaned)
        # Allow RFC 5737 documentation / fixture test IPs used for public simulation
        doc_nets = [
            ipaddress.ip_network("198.51.100.0/24"),
            ipaddress.ip_network("203.0.113.0/24"),
            ipaddress.ip_network("192.0.2.0/24")
        ]
        if ip_obj.version == 4 and any(ip_obj in net for net in doc_nets):
            return False

        if (
            ip_obj.is_private or
            ip_obj.is_loopback or
            ip_obj.is_reserved or
            ip_obj.is_multicast or
            ip_obj.is_unspecified or
            ip_obj.is_link_local
        ):
            return True
        # 6to4 prefix (2002::/16) utilized as internal datacenter hops by cloud providers
        if ip_obj.version == 6 and cleaned.lower().startswith("2002:"):
            return True
        # Explicit CGNAT (100.64.0.0/10)
        if ip_obj.version == 4 and ip_obj in ipaddress.ip_network("100.64.0.0/10"):
            return True
        return False
    except ValueError:
        return True

def extract_domain(email_or_host: str) -> Optional[str]:
    """Extract and normalize domain part from an email address or host."""
    if not email_or_host:
        return None
    val = email_or_host.strip().lower()
    if "@" in val:
        val = val.split("@")[-1]
    val = val.strip("<>[](),;:")
    # Remove leading subdomains if excessive, but keep domain
    parts = val.split(".")
    if len(parts) >= 2:
        return val
    return None

def get_base_domain(domain: Optional[str]) -> Optional[str]:
    """Extract base registered domain (e.g., mail.google.com -> google.com)."""
    if not domain:
        return None
    domain = domain.strip().lower().strip(".")
    parts = domain.split(".")
    if len(parts) <= 2:
        return domain
    # Common two-part TLDs (co.uk, com.au, edu.in, gov.in)
    two_part_tlds = {"co.uk", "com.au", "edu.in", "gov.in", "ac.in", "co.in", "net.in", "org.uk"}
    last_two = ".".join(parts[-2:])
    if last_two in two_part_tlds and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])

def parse_rfc5322_email(raw_content: bytes) -> email.message.EmailMessage:
    """Parse raw email bytes into an EmailMessage using modern policy."""
    try:
        return email.message_from_bytes(raw_content, policy=email.policy.default)
    except Exception:
        # Fallback to compat32 policy if default fails on malformed input
        return email.message_from_bytes(raw_content, policy=email.policy.compat32)

def validate_ip_token(token: Optional[str]) -> Optional[str]:
    """Validates an IP string using Python's ipaddress module. Discards non-IPs, Gmail 2002: IDs, and invalid formats."""
    if not token:
        return None
    cleaned = token.strip("[]():,; \t\r\n<>")
    if ":" in cleaned and "." in cleaned and cleaned.count(":") == 1:
        h_part, p_part = cleaned.split(":")
        if p_part.isdigit():
            cleaned = h_part
    if cleaned.lower().startswith("2002:"):
        return None
    try:
        ip_obj = ipaddress.ip_address(cleaned)
        return str(ip_obj)
    except ValueError:
        return None

def parse_received_hop(raw_hop: str, hop_number: int) -> RelayHop:
    """Extract structured attributes from a Received: header line."""
    hop_clean = " ".join(raw_hop.split())
    
    from_host = None
    from_ip = None
    by_host = None
    protocol = None
    timestamp_str = None
    parsed_dt = None

    # 1. Extract timestamp (everything after the final semicolon)
    if ";" in hop_clean:
        parts = hop_clean.rsplit(";", 1)
        time_part = parts[1].strip()
        try:
            parsed_dt = parsedate_to_datetime(time_part)
            if parsed_dt:
                if parsed_dt.tzinfo is None:
                    parsed_dt = parsed_dt.replace(tzinfo=timezone.utc)
                else:
                    parsed_dt = parsed_dt.astimezone(timezone.utc)
                timestamp_str = parsed_dt.isoformat()
        except Exception:
            timestamp_str = time_part
        hop_body = parts[0]
    else:
        hop_body = hop_clean

    # 2. Extract from_host and from_ip
    from_match = re.search(r'\bfrom\s+([^\s;]+)', hop_body, re.IGNORECASE)
    if from_match:
        from_host = from_match.group(1).strip("()[]")

    from_ip = None
    ip_matches = IPV4_REGEX.findall(hop_body)
    for cand in ip_matches:
        v = validate_ip_token(cand)
        if v:
            from_ip = v
            break
    if not from_ip:
        ip6_matches = IPV6_REGEX.findall(hop_body)
        for cand in ip6_matches:
            v = validate_ip_token(cand)
            if v:
                from_ip = v
                break

    # 3. Extract by_host
    by_match = re.search(r'\bby\s+([^\s;]+)', hop_body, re.IGNORECASE)
    if by_match:
        by_host = by_match.group(1).strip("()[]")

    # 4. Extract protocol (with ESMTPS, with SMTP, etc.)
    with_match = re.search(r'\bwith\s+([a-zA-Z0-9_-]+)', hop_body, re.IGNORECASE)
    if with_match:
        protocol = with_match.group(1).upper()

    is_priv = is_ip_private(from_ip) if from_ip else False

    return RelayHop(
        hop_number=hop_number,
        from_host=from_host,
        from_ip=from_ip,
        by_host=by_host,
        protocol=protocol,
        timestamp=timestamp_str,
        delay_seconds=None,
        delay_flag=None,
        is_private_ip=is_priv,
        raw=hop_clean
    )

def parse_auth_results(auth_headers: List[str], spf_headers: List[str]) -> Tuple[AuthStatus, AuthStatus, AuthStatus, List[str]]:
    """
    Parse RFC 8601/RFC 7601 Authentication-Results and Received-SPF headers.
    Returns normalized (spf, dkim, dmarc, raw_auth_results).
    """
    spf_verdict = "none"
    spf_details = None
    spf_domain = None

    dkim_verdict = "none"
    dkim_details = None
    dkim_domain = None
    dkim_selector = None

    dmarc_verdict = "none"
    dmarc_details = None
    dmarc_domain = None

    all_raw = list(auth_headers) + list(spf_headers)

    # 1. Parse Received-SPF if present
    for r_spf in spf_headers:
        r_spf_clean = " ".join(r_spf.split())
        match = re.match(r'^(pass|fail|softfail|neutral|none|temperror|permerror)', r_spf_clean, re.IGNORECASE)
        if match:
            spf_verdict = match.group(1).lower()
            spf_details = r_spf_clean
            dom_match = re.search(r'domain of ([^\s]+)', r_spf_clean, re.IGNORECASE)
            if dom_match:
                spf_domain = extract_domain(dom_match.group(1))

    # 2. Parse Authentication-Results (overrides or complements)
    for auth in auth_headers:
        auth_clean = " ".join(auth.split())
        
        # SPF token
        spf_m = re.search(r'\bspf=([a-zA-Z]+)(?:\s*\(([^)]*)\))?', auth_clean, re.IGNORECASE)
        if spf_m:
            spf_verdict = spf_m.group(1).lower()
            if spf_m.group(2):
                spf_details = spf_m.group(2)
            mailfrom_m = re.search(r'smtp\.mailfrom=([^\s;]+)', auth_clean, re.IGNORECASE)
            if mailfrom_m:
                spf_domain = extract_domain(mailfrom_m.group(1))

        # DKIM token
        dkim_m = re.search(r'\bdkim=([a-zA-Z]+)(?:\s*\(([^)]*)\))?', auth_clean, re.IGNORECASE)
        if dkim_m:
            dkim_verdict = dkim_m.group(1).lower()
            if dkim_m.group(2):
                dkim_details = dkim_m.group(2)
            d_match = re.search(r'header\.d=([^\s;]+)', auth_clean, re.IGNORECASE)
            if d_match:
                dkim_domain = d_match.group(1).strip()
            s_match = re.search(r'header\.s=([^\s;]+)', auth_clean, re.IGNORECASE)
            if s_match:
                dkim_selector = s_match.group(1).strip()

        # DMARC token
        dmarc_m = re.search(r'\bdmarc=([a-zA-Z]+)(?:\s*\(([^)]*)\))?', auth_clean, re.IGNORECASE)
        if dmarc_m:
            dmarc_verdict = dmarc_m.group(1).lower()
            if dmarc_m.group(2):
                dmarc_details = dmarc_m.group(2)
            from_m = re.search(r'header\.from=([^\s;]+)', auth_clean, re.IGNORECASE)
            if from_m:
                dmarc_domain = from_m.group(1).strip()

    spf_status = AuthStatus(verdict=spf_verdict, details=spf_details, domain=spf_domain)
    dkim_status = AuthStatus(verdict=dkim_verdict, details=dkim_details, domain=dkim_domain, selector=dkim_selector)
    dmarc_status = AuthStatus(verdict=dmarc_verdict, details=dmarc_details, domain=dmarc_domain)

    return spf_status, dkim_status, dmarc_status, all_raw

def parse_dkim_signatures(dkim_headers: List[str]) -> List[Dict[str, str]]:
    """Parse DKIM-Signature header tags into structured key-value maps."""
    signatures = []
    for sig in dkim_headers:
        tags = {}
        # Tags are semicolon separated: v=1; a=rsa-sha256; d=example.com; s=s2023; ...
        parts = sig.split(";")
        for part in parts:
            if "=" in part:
                k, v = part.split("=", 1)
                tags[k.strip().lower()] = v.strip()
        if tags:
            signatures.append(tags)
    return signatures

def analyze_email_headers(raw_bytes: bytes) -> ForensicAnalysisResponse:
    """
    Main forensic engine for Phase 1.
    Performs comprehensive header extraction, authentication check, and deep anomaly detection.
    """
    sha256_hash = hashlib.sha256(raw_bytes).hexdigest()
    msg = parse_rfc5322_email(raw_bytes)
    
    findings: List[ForensicFinding] = []
    risk_score = 0
    recommendations: List[str] = []

    # -------------------------------------------------------------
    # 1. ENVELOPE & HEADER EXTRACTION
    # -------------------------------------------------------------
    from_raw = msg.get("From", "")
    from_name, from_addr = parseaddr(from_raw)
    from_domain = extract_domain(from_addr)
    from_base = get_base_domain(from_domain)

    return_path_raw = msg.get("Return-Path", "")
    _, return_path_addr = parseaddr(return_path_raw)
    return_path_domain = extract_domain(return_path_addr)
    return_path_base = get_base_domain(return_path_domain)

    reply_to_raw = msg.get("Reply-To", "")
    reply_to_name, reply_to_addr = parseaddr(reply_to_raw)
    reply_to_domain = extract_domain(reply_to_addr)
    reply_to_base = get_base_domain(reply_to_domain)

    sender_raw = msg.get("Sender", "")
    subject = str(msg.get("Subject", ""))
    date_str = str(msg.get("Date", ""))
    message_id = str(msg.get("Message-ID", "")).strip()

    message_id_domain = None
    if "@" in message_id:
        m_dom = message_id.split("@")[-1].strip("<>")
        message_id_domain = extract_domain(m_dom)

    to_headers = [addr for _, addr in [parseaddr(t) for t in msg.get_all("To", [])] if addr]
    cc_headers = [addr for _, addr in [parseaddr(c) for c in msg.get_all("Cc", [])] if addr]
    bcc_headers = [addr for _, addr in [parseaddr(b) for b in msg.get_all("Bcc", [])] if addr]

    # Extract explicit origin IP candidate headers
    x_orig_raw = msg.get("X-Originating-IP")
    x_orig_ip = validate_ip_token(x_orig_raw) if x_orig_raw else None

    x_sender_raw = msg.get("X-Sender-IP")
    x_sender_ip = validate_ip_token(x_sender_raw) if x_sender_raw else None

    # Check alternative client headers if X-Originating-IP wasn't explicit
    if not x_orig_ip:
        client_ip_headers = ["X-Client-IP", "X-Forwarded-For", "X-Real-IP", "X-Apparently-From", "X-Original-IP", "X-Originating-Client-IP"]
        for hdr_name in client_ip_headers:
            val = msg.get(hdr_name)
            if val:
                v = validate_ip_token(val)
                if v and not is_ip_private(v):
                    x_orig_ip = v
                    break

    # Parse client-ip= parameter from Received-SPF headers
    spf_client_ip = None
    for spf_hdr in msg.get_all("Received-SPF", []):
        spf_m = re.search(r'client-ip=([0-9a-fA-F.:]+)', spf_hdr, re.IGNORECASE)
        if spf_m:
            v_spf = validate_ip_token(spf_m.group(1))
            if v_spf and not is_ip_private(v_spf):
                spf_client_ip = v_spf
                break

    user_agent = msg.get("User-Agent") or msg.get("X-Mailer") or None

    envelope = EmailEnvelope(
        from_header=from_raw,
        from_address=from_addr,
        from_display_name=from_name,
        from_domain=from_domain,
        return_path=return_path_addr or None,
        return_path_domain=return_path_domain,
        reply_to=reply_to_addr or None,
        reply_to_domain=reply_to_domain,
        sender=sender_raw or None,
        to=to_headers,
        cc=cc_headers,
        bcc=bcc_headers,
        subject=subject or None,
        date=date_str or None,
        message_id=message_id or None,
        message_id_domain=message_id_domain,
        x_originating_ip=x_orig_ip,
        x_sender_ip=x_sender_ip,
        spf_client_ip=spf_client_ip,
        user_agent=user_agent
    )

    # -------------------------------------------------------------
    # 2. RECEIVED CHAIN & RELAY PATH ANALYSIS
    # -------------------------------------------------------------
    raw_received = msg.get_all("Received", [])
    # Received headers in raw email are listed top-to-bottom (newest to oldest).
    # To reconstruct the true chronological relay path: reverse them (earliest = hop 1).
    chronological_raw = list(reversed(raw_received))
    relay_path: List[RelayHop] = []
    total_hops = len(chronological_raw)

    prev_dt = None
    time_inversion_detected = False

    for idx, r_hdr in enumerate(chronological_raw, start=1):
        hop = parse_received_hop(r_hdr, hop_number=idx)
        
        # Check chronological monotonicity and abnormal delay
        if hop.timestamp:
            try:
                curr_dt = datetime.fromisoformat(hop.timestamp)
                if curr_dt.tzinfo is None:
                    curr_dt = curr_dt.replace(tzinfo=timezone.utc)
                else:
                    curr_dt = curr_dt.astimezone(timezone.utc)

                if prev_dt is not None:
                    diff_seconds = (curr_dt - prev_dt).total_seconds()
                    hop.delay_seconds = round(diff_seconds, 2)
                    # Clock skew tolerance: allow up to 60 seconds backwards skew
                    if diff_seconds < -60:
                        hop.delay_flag = "TIME_INVERSION"
                        time_inversion_detected = True
                        findings.append(ForensicFinding(
                            id="RECEIVED_CHAIN_TIME_INVERSION",
                            severity="HIGH",
                            category="TRANSPORT",
                            title="Received Chain Chronological Inversion",
                            description=(
                                f"Hop #{idx} has a timestamp ({hop.timestamp}) earlier than preceding Hop #{idx-1}. "
                                f"Negative delay: {abs(diff_seconds):.0f}s. This indicates forged relay headers."
                            ),
                            technical_detail=f"Preceding hop timestamp: {prev_dt.isoformat()}, Current hop: {curr_dt.isoformat()}",
                            recommendation="Inspect MTA hostnames and untrusted upstream hops for forged headers."
                        ))
                        risk_score += 25
                    elif diff_seconds < 0:
                        hop.delay_flag = "CLOCK_SKEW"
                    elif diff_seconds > 86400:
                        hop.delay_flag = "EXTREME_DELAY"
                        findings.append(ForensicFinding(
                            id="EXTREME_TRANSPORT_DELAY",
                            severity="MEDIUM",
                            category="TRANSPORT",
                            title="Extreme Email Transport Delay (>24h)",
                            description=(
                                f"Hop #{idx} experienced an abnormal delivery latency of {diff_seconds / 3600:.1f} hours. "
                                "Substantial transport delays may indicate message spooling, greylisting evasion, or man-in-the-middle analysis."
                            ),
                            technical_detail=f"Delay between Hop #{idx-1} and #{idx}: {diff_seconds:.0f}s ({diff_seconds / 3600:.1f}h)",
                            recommendation="Review intermediate mail transfer agent logs to verify transmission legitimacy."
                        ))
                        risk_score += 10
                    else:
                        hop.delay_flag = "NORMAL"
                prev_dt = curr_dt
            except Exception:
                pass

        # Determine hop transmission role
        if total_hops == 1:
            if hop.is_private_ip:
                hop.hop_role = "INTERNAL_CLIENT_SUBMISSION"
            else:
                hop.hop_role = "INBOUND_GATEWAY"
        else:
            if idx == 1:
                if hop.is_private_ip:
                    hop.hop_role = "INTERNAL_CLIENT_SUBMISSION"
                else:
                    hop.hop_role = "PROBABLE_ORIGIN_INFRASTRUCTURE"
            elif idx == total_hops:
                hop.hop_role = "INBOUND_GATEWAY"
            else:
                hop.hop_role = "INTERMEDIATE_RELAY"

        # Multi-Hop Geolocation and Provider Relay Enrichment
        if hop.from_ip:
            if hop.is_private_ip:
                hop.country = "Private / Internal Network"
                hop.city = "Internal"
                hop.isp = "Local Network (RFC 1918)"
                hop.asn = None
            else:
                try:
                    from app.forensics.origin_tracer import enrich_ip_geolocation, check_provider_relay
                    geo = enrich_ip_geolocation(hop.from_ip)
                    hop.country = geo.country
                    hop.city = geo.city
                    hop.asn = geo.asn
                    hop.isp = geo.isp
                    is_prov, prov_name = check_provider_relay(geo=geo, ip_str=hop.from_ip)
                    hop.is_provider_relay = is_prov
                    hop.provider_name = prov_name
                except Exception:
                    pass
        
        relay_path.append(hop)

    # Check for empty or missing Received chain
    if not relay_path:
        findings.append(ForensicFinding(
            id="MISSING_RECEIVED_CHAIN",
            severity="MEDIUM",
            category="PROTOCOL",
            title="No Received Headers Found",
            description="Email source contains zero Received relay hops. Typical for fabricated or scrubbed emails.",
            technical_detail="No 'Received' headers present in RFC 5322 payload.",
            recommendation="Treat with caution; unable to verify sender infrastructure provenance."
        ))
        risk_score += 15

    # -------------------------------------------------------------
    # 3. AUTHENTICATION (SPF, DKIM, DMARC) ANALYSIS
    # -------------------------------------------------------------
    raw_auth_headers = msg.get_all("Authentication-Results", []) + msg.get_all("ARC-Authentication-Results", [])
    raw_spf_headers = msg.get_all("Received-SPF", [])
    raw_dkim_headers = msg.get_all("DKIM-Signature", [])

    spf_status, dkim_status, dmarc_status, all_raw_auth = parse_auth_results(raw_auth_headers, raw_spf_headers)
    dkim_signatures = parse_dkim_signatures(raw_dkim_headers)

    # Evaluate DKIM Alignment
    if dkim_signatures:
        primary_sig = dkim_signatures[0]
        sig_domain = primary_sig.get("d")
        sig_selector = primary_sig.get("s")
        if sig_domain:
            dkim_status.domain = sig_domain
            dkim_status.selector = sig_selector
            sig_base = get_base_domain(sig_domain)
            is_aligned = (from_base is not None and sig_base is not None and from_base == sig_base)
            dkim_status.aligned = is_aligned
            
            if not is_aligned:
                findings.append(ForensicFinding(
                    id="DKIM_DOMAIN_UNALIGNED",
                    severity="HIGH",
                    category="AUTHENTICATION",
                    title="DKIM Signature Domain Not Aligned",
                    description=(
                        f"Email is cryptographically signed by '{sig_domain}', but sender From domain is '{from_domain}'. "
                        "Unaligned DKIM signatures are frequently used by threat actors leveraging third-party email services."
                    ),
                    technical_detail=f"DKIM d={sig_domain}, s={sig_selector} vs From: {from_domain}",
                    recommendation="Verify whether the sender domain delegates mail delivery to this signing domain."
                ))
                risk_score += 20
    elif dkim_status.verdict in ["none", ""]:
        # No DKIM signature at all
        if from_domain and from_domain not in FREEMAIL_DOMAINS:
            findings.append(ForensicFinding(
                id="DKIM_SIGNATURE_MISSING",
                severity="LOW",
                category="AUTHENTICATION",
                title="Missing DKIM Cryptographic Signature",
                description=f"Domain '{from_domain}' did not sign this message with DomainKeys Identified Mail (DKIM).",
                technical_detail="No DKIM-Signature header present.",
                recommendation="Legitimate enterprise senders should cryptographically sign outbound messages."
            ))
            risk_score += 5

    # Check SPF verdict findings
    if spf_status.verdict == "fail":
        findings.append(ForensicFinding(
            id="SPF_VERIFICATION_FAILED",
            severity="HIGH",
            category="AUTHENTICATION",
            title="SPF Authentication Failed (Hard Fail)",
            description=f"Sending server is not authorized by the SPF record of domain '{from_domain or spf_status.domain}'.",
            technical_detail=spf_status.details or "SPF verdict: fail",
            recommendation="Reject or quarantine email. High likelihood of unauthorized IP spoofing."
        ))
        risk_score += 25
    elif spf_status.verdict == "softfail":
        findings.append(ForensicFinding(
            id="SPF_VERIFICATION_SOFTFAIL",
            severity="MEDIUM",
            category="AUTHENTICATION",
            title="SPF SoftFail Warning",
            description=f"Sending IP is in transitional / softfail status for domain '{from_domain or spf_status.domain}'.",
            technical_detail=spf_status.details or "SPF verdict: softfail",
            recommendation="Scrutinize sender IP and relay hops."
        ))
        risk_score += 15

    # Check DMARC verdict findings
    if dmarc_status.verdict == "fail":
        findings.append(ForensicFinding(
            id="DMARC_POLICY_FAILED",
            severity="CRITICAL",
            category="AUTHENTICATION",
            title="DMARC Policy Enforcement Failed",
            description=f"Message failed Domain-based Message Authentication (DMARC) alignment for '{from_domain}'.",
            technical_detail=dmarc_status.details or "DMARC verdict: fail",
            recommendation="Drop message or isolate in quarantine sandbox."
        ))
        risk_score += 30

    # -------------------------------------------------------------
    # 4. IDENTITY & DISPLAY NAME ANOMALY DETECTION
    # -------------------------------------------------------------
    # Anomaly 4.1: Display Name Email Injection (e.g., "security@paypal.com" <scammer@evil.com>)
    if from_name:
        embedded_emails = IPV4_REGEX.findall(from_name)  # check IPs or emails
        email_in_name = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', from_name)
        if email_in_name:
            injected_email = email_in_name[0].lower()
            if from_addr and injected_email != from_addr.lower():
                findings.append(ForensicFinding(
                    id="DISPLAY_NAME_EMAIL_SPOOFING",
                    severity="CRITICAL",
                    category="IDENTITY_SPOOFING",
                    title="Display Name Email Injection",
                    description=(
                        f"Sender display name embeds an email address ('{injected_email}') that does not match "
                        f"the actual sender address ('{from_addr}'). This is an evasive impersonation tactic."
                    ),
                    technical_detail=f"Display Name: '{from_name}' | Envelope From: '{from_addr}'",
                    recommendation="Do not trust sender identity. High-confidence phishing indicator."
                ))
                risk_score += 35

    # Anomaly 4.2: Brand Impersonation in Display Name
    if from_name:
        name_lower = from_name.lower()
        for brand, legitimate_domains in HIGH_VALUE_BRANDS.items():
            # Match brand whole-word in display name
            if re.search(r'\b' + re.escape(brand) + r'\b', name_lower):
                # Check if sender domain matches any legitimate brand domain
                is_legit_brand = False
                if from_domain:
                    for legit in legitimate_domains:
                        if from_domain == legit or from_domain.endswith("." + legit):
                            is_legit_brand = True
                            break
                if not is_legit_brand:
                    findings.append(ForensicFinding(
                        id="BRAND_IMPERSONATION_DISPLAY_NAME",
                        severity="HIGH",
                        category="IDENTITY_SPOOFING",
                        title=f"Brand Impersonation: {brand.title()}",
                        description=(
                            f"Display name claims to represent '{brand.title()}', but sending domain is '{from_domain or 'unknown'}', "
                            f"which does not belong to authorized brand domains ({', '.join(legitimate_domains[:2])})."
                        ),
                        technical_detail=f"Display Name: '{from_name}' | Actual Domain: '{from_domain}'",
                        recommendation="Block sender and alert recipient about brand credential-harvesting attempt."
                    ))
                    risk_score += 25
                    break

    # Anomaly 4.3: From vs Return-Path Domain Mismatch
    if from_base and return_path_base and from_base != return_path_base:
        findings.append(ForensicFinding(
            id="FROM_RETURN_PATH_MISMATCH",
            severity="HIGH",
            category="IDENTITY_SPOOFING",
            title="From vs Return-Path Domain Mismatch",
            description=(
                f"The From address domain ('{from_domain}') differs from the Return-Path bounce domain ('{return_path_domain}'). "
                "While common in mass marketing ESPs, in targeted emails this indicates envelope sender spoofing."
            ),
            technical_detail=f"From Domain: {from_domain} (base: {from_base}) vs Return-Path Domain: {return_path_domain} (base: {return_path_base})",
            recommendation="Cross-check SPF record of Return-Path vs From to verify authorized delegation."
        ))
        risk_score += 20

    # Anomaly 4.4: From vs Reply-To Mismatch (BEC / Communication Hijacking)
    if reply_to_addr and from_addr and reply_to_addr.lower() != from_addr.lower():
        is_freemail_diversion = reply_to_domain in FREEMAIL_DOMAINS and from_domain not in FREEMAIL_DOMAINS
        severity = "CRITICAL" if is_freemail_diversion else "HIGH"
        
        desc = (
            f"Replies are routed to '{reply_to_addr}' instead of the sender address '{from_addr}'."
        )
        if is_freemail_diversion:
            desc += f" 🚨 CRITICAL: The reply address uses a public webmail service ({reply_to_domain}) while sender claims enterprise domain '{from_domain}'. Hallmark of Business Email Compromise (BEC)."

        findings.append(ForensicFinding(
            id="REPLY_TO_DIVERSION",
            severity=severity,
            category="IDENTITY_SPOOFING",
            title="Reply-To Address Diversion (BEC Indicator)",
            description=desc,
            technical_detail=f"From: {from_addr} -> Reply-To: {reply_to_addr}",
            recommendation="Do not send sensitive files, banking details, or wire confirmations to this Reply-To address."
        ))
        risk_score += 35 if is_freemail_diversion else 20

    # Anomaly 4.5: Message-ID Domain Mismatch
    if message_id:
        if message_id_domain and from_base:
            mid_base = get_base_domain(message_id_domain)
            # Check if mid matches From, Return-Path, or any relay MTA
            mta_domains = [get_base_domain(h.by_host) for h in relay_path if h.by_host]
            mta_domains.extend([get_base_domain(h.from_host) for h in relay_path if h.from_host])
            
            if mid_base != from_base and mid_base != return_path_base and mid_base not in mta_domains:
                findings.append(ForensicFinding(
                    id="MESSAGE_ID_DOMAIN_MISMATCH",
                    severity="MEDIUM",
                    category="PROTOCOL",
                    title="Message-ID Domain Discrepancy",
                    description=(
                        f"Message-ID domain ('{message_id_domain}') does not correspond to sender domain ('{from_domain}') "
                        "or any transmitting Mail Transfer Agent in the relay chain."
                    ),
                    technical_detail=f"Message-ID: {message_id} | Domain: {message_id_domain}",
                    recommendation="Investigate client email software and relay hops."
                ))
                risk_score += 10
    else:
        findings.append(ForensicFinding(
            id="MISSING_MESSAGE_ID",
            severity="LOW",
            category="PROTOCOL",
            title="Missing Message-ID Header",
            description="RFC 5322 requires a unique Message-ID header for tracking. Missing in this email.",
            technical_detail="Message-ID header is empty or absent.",
            recommendation="Scrutinize sender origin; automated spam scripts often omit Message-ID."
        ))
        risk_score += 5

    # -------------------------------------------------------------
    # 5. ORIGIN TRACING & GEOLOCATION (Phase 2)
    # -------------------------------------------------------------
    from app.forensics.origin_tracer import analyze_origin_and_geolocation
    origin_trace, origin_findings = analyze_origin_and_geolocation(
        relay_path, envelope.x_originating_ip
    )
    findings.extend(origin_findings)
    for of in origin_findings:
        if of.severity == "CRITICAL":
            risk_score += 35
        elif of.severity == "HIGH":
            risk_score += 20
        elif of.severity == "MEDIUM":
            risk_score += 10

    # -------------------------------------------------------------
    # 6. DOMAIN INTELLIGENCE & LOOKALIKE DETECTION (Phase 2)
    # -------------------------------------------------------------
    from app.forensics.domain_intel import analyze_domain_intel
    domain_intel, domain_findings = analyze_domain_intel(envelope.from_domain)
    findings.extend(domain_findings)
    for df in domain_findings:
        if df.severity == "CRITICAL":
            risk_score += 35
        elif df.severity == "HIGH":
            risk_score += 25
        elif df.severity == "MEDIUM":
            risk_score += 10

    # -------------------------------------------------------------
    # 7. NLP LINGUISTIC THREAT ANALYSIS & MULTI-CLASS INFERENCE
    # -------------------------------------------------------------
    email_body_text = ""
    email_raw_content = ""
    try:
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))
                if "attachment" not in content_disposition:
                    payload = part.get_payload(decode=True)
                    if payload:
                        decoded = payload.decode("utf-8", errors="replace")
                        email_raw_content += decoded + " "
                        if content_type == "text/plain":
                            email_body_text += decoded + " "
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                email_raw_content = payload.decode("utf-8", errors="replace")
                email_body_text = email_raw_content
            else:
                email_raw_content = str(msg.get_payload() or "")
                email_body_text = email_raw_content
    except Exception:
        email_body_text = ""
        email_raw_content = ""

    full_nlp_text = f"{subject} {email_body_text}".strip()
    from app.ml.model import predict_email_category
    nlp_res = predict_email_category(full_nlp_text) if full_nlp_text else {
        "category": "legitimate", "confidence": 0.6, "threat_probability": 0.0, "is_threat": False, "probabilities": {}
    }

    # Add NLP Finding if threat detected
    if nlp_res.get("is_threat"):
        cat = nlp_res.get("category", "phishing")
        conf = nlp_res.get("confidence", 0.0)
        findings.append(ForensicFinding(
            id=f"AI_NLP_{cat.upper()}_DETECTED",
            severity="CRITICAL" if cat in ["bec_fraud", "phishing"] and conf >= 0.75 else "HIGH",
            category="LURE",
            title=f"AI Threat Engine: {cat.replace('_', ' ').title()} Patterns",
            description=f"AI NLP Classifier detected {cat.replace('_', ' ')} language patterns with {conf*100:.1f}% confidence.",
            technical_detail=f"Predicted Class: {cat} | Probabilities: {nlp_res.get('probabilities')}",
            recommendation="Review email body lure and verify sender out-of-band before taking action."
        ))

    # -------------------------------------------------------------
    # 8. ALTERNATIVE INFRASTRUCTURE EVIDENCE (Task 2)
    # -------------------------------------------------------------
    url_pattern = re.compile(r'https?://[^\s<>"\'\)\]\}]+', re.IGNORECASE)
    extracted_urls = list(dict.fromkeys(url_pattern.findall(email_raw_content)))

    from app.forensics.infra_intel import gather_alternative_infrastructure_evidence
    infra_evidence, infra_findings = gather_alternative_infrastructure_evidence(
        origin_status=origin_trace.origin_status if origin_trace else "ORIGIN_FOUND",
        from_address=envelope.from_address or "",
        reply_to_address=envelope.reply_to,
        urls=extracted_urls
    )
    if infra_findings:
        findings.extend(infra_findings)

    # -------------------------------------------------------------
    # 9. MULTI-FACTOR FRAUD SCORE FUSION (Phase 3)
    # -------------------------------------------------------------
    auth_forensics = AuthenticationForensics(
        spf=spf_status,
        dkim=dkim_status,
        dmarc=dmarc_status,
        raw_auth_results=all_raw_auth,
        raw_dkim_signatures=raw_dkim_headers
    )

    from app.forensics.fraud_scorer import compute_fused_fraud_score
    fraud_breakdown = compute_fused_fraud_score(
        nlp_result=nlp_res,
        envelope=envelope,
        auth=auth_forensics,
        findings=findings,
        origin_trace=origin_trace,
        domain_intel=domain_intel,
        infra_evidence=infra_evidence
    )

    crit_count = sum(1 for f in findings if f.severity == "CRITICAL")
    high_count = sum(1 for f in findings if f.severity == "HIGH")
    med_count = sum(1 for f in findings if f.severity == "MEDIUM")
    low_count = sum(1 for f in findings if f.severity == "LOW")

    if fraud_breakdown.risk_tier == "CRITICAL":
        recommendations.append("Immediate isolation recommended. Block sender domain and envelope return path.")
        recommendations.append("Conduct compromise assessment on any internal accounts contacted.")
    elif fraud_breakdown.risk_tier == "HIGH":
        recommendations.append("Verify sender out-of-band via verified corporate directory.")
        recommendations.append("Do not click links, process invoices, or download attachments.")
    elif fraud_breakdown.risk_tier == "MEDIUM":
        recommendations.append("Proceed with caution. Verify sender and inspect links.")
    else:
        recommendations.append("Routine monitoring. Headers, authentication, and origin align.")

    summary = ForensicSummary(
        verdict=fraud_breakdown.predicted_category.upper(),
        risk_score=fraud_breakdown.overall_score,
        confidence=round(min(0.99, max(0.60, (fraud_breakdown.overall_score / 100.0) * 0.4 + 0.6)), 2),
        total_findings=len(findings),
        critical_findings=crit_count,
        high_findings=high_count,
        medium_findings=med_count,
        low_findings=low_count,
        executive_summary=f"Risk Tier: {fraud_breakdown.risk_tier} (Score: {fraud_breakdown.overall_score}/100). Primary Driver: {fraud_breakdown.primary_risk_driver}"
    )

    from app.correlation.attribution import attribute_threat_origin
    origin_attr = attribute_threat_origin(
        envelope=envelope,
        auth=auth_forensics,
        findings=findings,
        origin_trace=origin_trace,
        domain_intel=domain_intel,
        fraud_score=fraud_breakdown,
        infra_evidence=infra_evidence
    )

    res = ForensicAnalysisResponse(
        sha256=sha256_hash,
        ingested_at=datetime.now(timezone.utc).isoformat(),
        summary=summary,
        fraud_score=fraud_breakdown,
        attribution=origin_attr,
        envelope=envelope,
        authentication=auth_forensics,
        relay_path=relay_path,
        origin_trace=origin_trace,
        domain_intel=domain_intel,
        infrastructure_evidence=infra_evidence,
        findings=findings,
        security_recommendations=recommendations
    )

    try:
        from app.correlation.graph import build_single_forensic_graph
        res.threat_graph = build_single_forensic_graph(res)
    except Exception:
        pass

    return res


