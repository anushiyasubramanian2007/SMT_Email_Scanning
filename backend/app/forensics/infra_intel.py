"""
PhishingGuard Forensics: Alternative Infrastructure Evidence Engine
Gathers corroborating threat telemetry when sender real IP is concealed (PROVIDER_RELAY / ANONYMIZED).
Performs cached, timeout-protected, fail-safe lookups:
1. resolve_link_infra: Link domain resolution, ASN, bulletproof/VPS hosting detection, redirect expansion (HEAD only), homoglyphs, raw-IP, @-tricks.
2. resolve_mx_infra: Top MX host resolution, IP geolocation, ASN, hosting evaluation.
3. resolve_whois_intel: WHOIS creation age, registrar, country, NRD flag (<30d), privacy detection without fabrication.
4. resolve_reply_to_infra: Reply-To domain divergence analysis, secondary MX + WHOIS resolution.
"""

import os
import re
import json
import socket
import urllib.parse
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Tuple, Any

import requests
import dns.resolver

try:
    import whois
except ImportError:
    whois = None

from app.database.db import SessionLocal, IntelCache
from app.schemas.forensic_schemas import (
    LinkInfrastructure,
    MxInfrastructure,
    WhoisIntel,
    ReplyToInfrastructure,
    InfrastructureEvidence,
    ForensicFinding
)
from app.forensics.origin_tracer import enrich_ip_geolocation, KNOWN_PROVIDER_ASNS
from app.forensics.header_analyzer import extract_domain, get_base_domain, is_ip_private, validate_ip_token

# Configurable suspicious / bulletproof / VPS hosting ASNs frequently used for phishing landing pages
SUSPICIOUS_HOSTING_ASNS: Dict[str, str] = {
    "24940": "Hetzner Online GmbH",
    "16276": "OVH SAS",
    "14061": "DigitalOcean, LLC",
    "20473": "Choopa, LLC / Vultr",
    "63949": "Linode, LLC / Akamai",
    "47583": "Hostinger International",
    "51167": "Contabo GmbH",
    "60781": "Leaseweb",
    "12876": "Scaleway",
    "62240": "M247 Ltd",
    "46652": "Hostwinds",
    "55720": "BisectHosting",
    "197695": "Reg.ru Hosting",
    "49453": "Global Layer B.V."
}

# Suspicious hosting provider keywords in ISP or Org
SUSPICIOUS_HOSTING_KEYWORDS = [
    "hetzner", "ovh", "digitalocean", "vultr", "choopa", "linode",
    "hostinger", "contabo", "leaseweb", "scaleway", "m247", "bulletproof",
    "offshore", "vps", "hostwinds", "cheap hosting"
]

# Common URL Shortener domains that disguise final destinations
KNOWN_URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly",
    "is.gd", "cutt.ly", "rebrand.ly", "bl.ink", "shorturl.at", "tiny.cc",
    "rb.gy", "hyperurl.co", "soo.gd", "s.id", "v.gd"
}

# Target high-value brands for IDN / homoglyph detection on link domains
LINK_PROTECTED_BRANDS = [
    "paypal", "microsoft", "google", "apple", "amazon", "netflix",
    "chase", "bankofamerica", "wellsfargo", "citibank", "dhl", "fedex",
    "ups", "irs", "facebook", "instagram", "linkedin", "dropbox",
    "coinbase", "binance", "outlook", "office365", "walmart"
]

# Configurable cache TTL (hours)
INTEL_CACHE_TTL_HOURS = int(os.getenv("INTEL_CACHE_TTL_HOURS", "24"))

# =========================================================================
# Cache Helpers (SQLite intel_cache)
# =========================================================================

def get_cached_intel(intel_type: str, cache_key: str) -> Optional[Dict[str, Any]]:
    """Retrieve unexpired cached intel from SQLite."""
    db = SessionLocal()
    try:
        cutoff = datetime.utcnow() - timedelta(hours=INTEL_CACHE_TTL_HOURS)
        entry = db.query(IntelCache).filter(
            IntelCache.intel_type == intel_type,
            IntelCache.cache_key == cache_key,
            IntelCache.created_at >= cutoff
        ).first()
        if entry and entry.data_json:
            return json.loads(entry.data_json)
    except Exception:
        pass
    finally:
        db.close()
    return None

def set_cached_intel(intel_type: str, cache_key: str, data: Dict[str, Any]):
    """Persist intel record to SQLite intel_cache table."""
    db = SessionLocal()
    try:
        new_entry = IntelCache(
            intel_type=intel_type,
            cache_key=cache_key,
            data_json=json.dumps(data),
            created_at=datetime.utcnow()
        )
        db.add(new_entry)
        db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()

# =========================================================================
# 1. URL & Link Infrastructure Intelligence
# =========================================================================

def check_suspicious_hosting(asn_str: Optional[str], isp_str: Optional[str], org_str: Optional[str]) -> Tuple[bool, Optional[str]]:
    """Check if ASN, ISP, or Org matches known bulletproof or commercial VPS hosting."""
    if asn_str:
        digits = "".join(re.findall(r'\d+', asn_str.split()[0]))
        if digits in SUSPICIOUS_HOSTING_ASNS:
            return True, SUSPICIOUS_HOSTING_ASNS[digits]

    desc = f"{asn_str or ''} {isp_str or ''} {org_str or ''}".lower()
    for kw in SUSPICIOUS_HOSTING_KEYWORDS:
        if kw in desc:
            return True, kw.title()

    return False, None

def follow_url_redirects_head(url: str, max_redirects: int = 5, timeout: float = 3.0) -> Tuple[str, List[str]]:
    """
    Follow HTTP redirect hops using strictly read-only HEAD requests.
    Never downloads response bodies.
    """
    hops = [url]
    current_url = url
    headers = {"User-Agent": "PhishingGuard-Forensics-HeadProbe/2.0"}

    for _ in range(max_redirects):
        try:
            resp = requests.head(current_url, allow_redirects=False, timeout=timeout, headers=headers)
            if resp.status_code in [301, 302, 303, 307, 308]:
                location = resp.headers.get("Location")
                if not location:
                    break
                next_url = urllib.parse.urljoin(current_url, location)
                if next_url in hops:
                    break  # Circular redirect loop detected
                hops.append(next_url)
                current_url = next_url
            else:
                break
        except Exception:
            break

    return current_url, hops

def resolve_link_infra(urls: List[str]) -> Tuple[List[LinkInfrastructure], List[ForensicFinding]]:
    """
    Inspects each unique URL in the email:
    Resolves domain to IP, checks ASN/hosting, detects shorteners via HEAD requests,
    identifies punycode/homoglyphs, raw-IP destinations, and @-symbol tricks.
    """
    results: List[LinkInfrastructure] = []
    findings: List[ForensicFinding] = []
    seen_urls = set()

    for raw_url in urls:
        url_clean = raw_url.strip()
        if not url_clean or url_clean in seen_urls:
            continue
        seen_urls.add(url_clean)

        # 1. Check SQLite Cache
        cached = get_cached_intel("LINK_INFRA", url_clean)
        if cached:
            item = LinkInfrastructure(**cached)
            results.append(item)
            if item.is_suspicious_hosting:
                findings.append(ForensicFinding(
                    id="SUSPICIOUS_LINK_HOSTING",
                    severity="HIGH",
                    category="INFRASTRUCTURE",
                    title="Phishing Link Hosted on Bulletproof / VPS Provider",
                    description=f"Destination link '{item.url[:60]}...' is hosted on known VPS/bulletproof provider ({item.suspicious_hosting_provider}).",
                    technical_detail=f"URL: {item.url} | Resolved IP: {item.resolved_ip} | ASN: {item.asn} | Provider: {item.suspicious_hosting_provider}",
                    recommendation="Block URL immediately. Bulletproof infrastructure strongly correlates with active threat operations."
                ))
            if item.is_shortener and len(item.redirect_hops) > 1:
                findings.append(ForensicFinding(
                    id="URL_SHORTENER_OBSCURATION",
                    severity="MEDIUM",
                    category="LURE",
                    title="URL Shortener Redirect Obscuration",
                    description=f"Link utilizes shortening service to conceal destination: '{item.final_url[:60]}...'.",
                    technical_detail=f"Original: {item.url} -> Final: {item.final_url} (Hops: {len(item.redirect_hops)})",
                    recommendation="Inspect final expanded destination before trusting link."
                ))
            continue

        # 2. Check for @ symbol trick in URL (e.g. https://google.com@evil.com/login)
        has_at = "@" in urllib.parse.urlsplit(url_clean).netloc

        # 3. Check for URL Shortener & Expand via HEAD requests
        parsed_orig = urllib.parse.urlsplit(url_clean)
        orig_domain = parsed_orig.netloc.split(":")[0].lower()
        is_shortener = orig_domain in KNOWN_URL_SHORTENERS

        final_url = url_clean
        redirect_hops = [url_clean]
        if is_shortener:
            final_url, redirect_hops = follow_url_redirects_head(url_clean, max_redirects=5, timeout=3.0)

        # Parse target domain from final URL
        parsed_final = urllib.parse.urlsplit(final_url)
        target_host = parsed_final.netloc.split(":")[0].lower()
        if "@" in target_host:
            target_host = target_host.split("@")[-1]

        # 4. Check for Raw-IP URL
        is_raw_ip = bool(validate_ip_token(target_host))

        # 5. Check for IDN Homoglyph / Punycode
        has_idn = target_host.startswith("xn--") or ".xn--" in target_host
        if not has_idn:
            for b in LINK_PROTECTED_BRANDS:
                if b in target_host and not target_host.endswith(f"{b}.com"):
                    # Brand substring in host
                    has_idn = True
                    break

        # 6. Resolve Domain -> IP
        resolved_ip = None
        if is_raw_ip:
            resolved_ip = validate_ip_token(target_host)
        elif target_host:
            try:
                # DNS query with timeout
                answers = socket.getaddrinfo(target_host, None, socket.AF_INET)
                if answers:
                    resolved_ip = answers[0][4][0]
            except Exception:
                pass

        # 7. Geolocate & Enrich Resolved IP
        geo_intel = None
        is_susp_hosting = False
        susp_provider = None
        if resolved_ip and not is_ip_private(resolved_ip):
            geo_intel = enrich_ip_geolocation(resolved_ip)
            is_susp_hosting, susp_provider = check_suspicious_hosting(geo_intel.asn, geo_intel.isp, geo_intel.org)

        link_obj = LinkInfrastructure(
            url=url_clean,
            domain=target_host or orig_domain,
            resolved_ip=resolved_ip,
            asn=geo_intel.asn if geo_intel else None,
            isp=geo_intel.isp if geo_intel else None,
            country=geo_intel.country if geo_intel else None,
            city=geo_intel.city if geo_intel else None,
            latitude=geo_intel.latitude if geo_intel else None,
            longitude=geo_intel.longitude if geo_intel else None,
            is_suspicious_hosting=is_susp_hosting,
            suspicious_hosting_provider=susp_provider,
            final_url=final_url if final_url != url_clean else None,
            is_shortener=is_shortener,
            redirect_hops=redirect_hops,
            has_idn_homoglyph=has_idn,
            is_raw_ip=is_raw_ip,
            has_at_symbol=has_at
        )

        # Cache in SQLite
        set_cached_intel("LINK_INFRA", url_clean, link_obj.model_dump())
        results.append(link_obj)

        # Generate Findings
        if is_susp_hosting:
            findings.append(ForensicFinding(
                id="SUSPICIOUS_LINK_HOSTING",
                severity="HIGH",
                category="INFRASTRUCTURE",
                title="Phishing Link Hosted on Bulletproof / VPS Provider",
                description=f"Destination link '{url_clean[:60]}...' is hosted on known VPS/bulletproof provider ({susp_provider}).",
                technical_detail=f"URL: {url_clean} | Resolved IP: {resolved_ip} | ASN: {geo_intel.asn if geo_intel else 'N/A'} | Provider: {susp_provider}",
                recommendation="Block URL immediately. Bulletproof infrastructure strongly correlates with active threat operations."
            ))
        if is_shortener and len(redirect_hops) > 1:
            findings.append(ForensicFinding(
                id="URL_SHORTENER_OBSCURATION",
                severity="MEDIUM",
                category="LURE",
                title="URL Shortener Redirect Obscuration",
                description=f"Link utilizes shortening service to conceal destination: '{final_url[:60]}...'.",
                technical_detail=f"Original: {url_clean} -> Final: {final_url} (Hops: {len(redirect_hops)})",
                recommendation="Inspect final expanded destination before trusting link."
            ))
        if is_raw_ip:
            findings.append(ForensicFinding(
                id="RAW_IP_URL_DESTINATION",
                severity="HIGH",
                category="INFRASTRUCTURE",
                title="Direct IP-Address Link Destination",
                description=f"Link targets a raw IP address ({target_host}) instead of a registered domain.",
                technical_detail=f"Raw IP URL: {url_clean}",
                recommendation="Legitimate businesses almost never route users to direct IP addresses."
            ))
        if has_idn:
            findings.append(ForensicFinding(
                id="IDN_HOMOGLYPH_LINK",
                severity="CRITICAL",
                category="IDENTITY_SPOOFING",
                title="IDN Homoglyph / Punycode Deception in Link",
                description=f"Link '{url_clean}' uses non-ASCII homoglyphs (punycode: {target_host}) to mimic another brand.",
                technical_detail=f"URL: {url_clean} | Target Host: {target_host}",
                recommendation="Block URL immediately; punycode homoglyphs are used for targeted spoofing."
            ))
        if has_at:
            findings.append(ForensicFinding(
                id="URL_AT_SYMBOL_OBFUSCATION",
                severity="HIGH",
                category="IDENTITY_SPOOFING",
                title="Deceptive URL '@' Authority Trick",
                description="URL includes '@' character to deceive users into believing they are visiting the prefix domain.",
                technical_detail=f"URL: {url_clean} | Real destination host: {target_host}",
                recommendation="Treat with extreme suspicion. This is a classic credential harvesting evasion technique."
            ))

    return results, findings

# =========================================================================
# 2. MX Infrastructure Intelligence
# =========================================================================

def resolve_mx_infra(domain: Optional[str]) -> Tuple[Optional[MxInfrastructure], List[ForensicFinding]]:
    """
    Looks up top MX record for domain, resolves host to IP, and evaluates hosting and geolocation.
    """
    if not domain:
        return None, []

    domain_clean = domain.strip().lower().strip(".")
    findings: List[ForensicFinding] = []

    # Check cache
    cached = get_cached_intel("MX_INFRA", domain_clean)
    if cached:
        mx_res = MxInfrastructure(**cached)
        return mx_res, []

    primary_mx = None
    resolved_ip = None
    geo_intel = None
    is_susp = False
    susp_prov = None

    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2.0
        resolver.lifetime = 2.5
        answers = resolver.resolve(domain_clean, "MX")
        if answers:
            # Sort by preference and pick top
            sorted_answers = sorted(answers, key=lambda r: r.preference)
            primary_mx = str(sorted_answers[0].exchange).rstrip(".")
    except Exception:
        pass

    if primary_mx:
        try:
            addr_info = socket.getaddrinfo(primary_mx, None, socket.AF_INET)
            if addr_info:
                resolved_ip = addr_info[0][4][0]
        except Exception:
            pass

    if resolved_ip and not is_ip_private(resolved_ip):
        geo_intel = enrich_ip_geolocation(resolved_ip)
        is_susp, susp_prov = check_suspicious_hosting(geo_intel.asn, geo_intel.isp, geo_intel.org)

    mx_obj = MxInfrastructure(
        domain=domain_clean,
        primary_mx=primary_mx,
        resolved_ip=resolved_ip,
        asn=geo_intel.asn if geo_intel else None,
        isp=geo_intel.isp if geo_intel else None,
        country=geo_intel.country if geo_intel else None,
        city=geo_intel.city if geo_intel else None,
        latitude=geo_intel.latitude if geo_intel else None,
        longitude=geo_intel.longitude if geo_intel else None,
        is_suspicious_hosting=is_susp,
        suspicious_hosting_provider=susp_prov
    )

    set_cached_intel("MX_INFRA", domain_clean, mx_obj.model_dump())
    return mx_obj, findings

# =========================================================================
# 3. WHOIS Intelligence (Creation date, registrar, NRD flag, privacy check)
# =========================================================================

def resolve_whois_intel(domain: Optional[str], timeout: float = 3.0) -> Tuple[WhoisIntel, List[ForensicFinding]]:
    """
    Queries WHOIS creation date, registrar, and registrant country.
    Flags newly_registered if < 30 days old.
    Returns available=False if WHOIS fails or is privacy-protected/redacted (never fabricates).
    """
    if not domain:
        return WhoisIntel(domain="unknown", available=False), []

    domain_clean = domain.strip().lower().strip(".")
    base_dom = get_base_domain(domain_clean) or domain_clean
    findings: List[ForensicFinding] = []

    # Check cache
    cached = get_cached_intel("WHOIS_INTEL", base_dom)
    if cached:
        w_res = WhoisIntel(**cached)
        if w_res.is_newly_registered:
            findings.append(ForensicFinding(
                id="NEWLY_REGISTERED_DOMAIN",
                severity="HIGH",
                category="INFRASTRUCTURE",
                title="Newly Registered Domain (Age < 30 Days)",
                description=f"Domain '{base_dom}' was registered {w_res.domain_age_days} days ago. Threat actors routinely leverage newly registered domains.",
                technical_detail=f"Domain: {base_dom} | Age: {w_res.domain_age_days}d | Registrar: {w_res.registrar or 'N/A'}",
                recommendation="Isolate communications originating from newly registered domain infrastructure."
            ))
        return w_res, findings

    creation_dt = None
    age_days = None
    registrar = None
    registrant_country = None
    is_nrd = False
    is_available = False

    try:
        if whois is None:
            return WhoisIntel(domain=base_dom, available=False), []

        # Protect with timeout
        orig_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        try:
            w = whois.whois(base_dom)
        finally:
            socket.setdefaulttimeout(orig_timeout)

        if w and (w.creation_date or w.registrar):
            c_date = w.creation_date
            if isinstance(c_date, list):
                c_date = c_date[0]

            registrar = str(w.registrar or "") or None
            registrant_country = str(w.country or "") or None

            # Detect WHOIS Privacy Guard
            privacy_keywords = ["privacy", "redacted", "whoisguard", "proxy", "withheld", "protected", "gdpr"]
            raw_text = str(w).lower()
            is_privacy_protected = any(pk in raw_text for pk in privacy_keywords)

            if c_date and isinstance(c_date, datetime):
                if c_date.tzinfo is not None:
                    c_date = c_date.astimezone(timezone.utc).replace(tzinfo=None)
                now = datetime.utcnow()
                age_days = (now - c_date).days
                is_nrd = (age_days < 30) if age_days >= 0 else False
                creation_dt = c_date.isoformat()
                is_available = True
            elif registrar and not is_privacy_protected:
                is_available = True
            elif is_privacy_protected:
                # Privacy protected: state available=False per specification
                is_available = False
    except Exception:
        is_available = False

    whois_obj = WhoisIntel(
        domain=base_dom,
        available=is_available,
        creation_date=creation_dt,
        domain_age_days=age_days,
        registrar=registrar,
        registrant_country=registrant_country,
        is_newly_registered=is_nrd
    )

    set_cached_intel("WHOIS_INTEL", base_dom, whois_obj.model_dump())

    if is_nrd:
        findings.append(ForensicFinding(
            id="NEWLY_REGISTERED_DOMAIN",
            severity="HIGH",
            category="INFRASTRUCTURE",
            title="Newly Registered Domain (Age < 30 Days)",
            description=f"Domain '{base_dom}' was registered {age_days} days ago. Threat actors routinely leverage newly registered domains.",
            technical_detail=f"Domain: {base_dom} | Age: {age_days}d | Registrar: {registrar or 'N/A'}",
            recommendation="Isolate communications originating from newly registered domain infrastructure."
        ))

    return whois_obj, findings

# =========================================================================
# 4. Reply-To Infrastructure Intelligence
# =========================================================================

def resolve_reply_to_infra(from_addr: Optional[str], reply_to_addr: Optional[str]) -> Tuple[Optional[ReplyToInfrastructure], List[ForensicFinding]]:
    """
    If Reply-To domain differs from From domain, runs MX + WHOIS on the Reply-To domain
    and flags reply_to_mismatch. Returns None if they match.
    """
    if not from_addr or not reply_to_addr:
        return None, []

    from_dom = extract_domain(from_addr)
    reply_to_dom = extract_domain(reply_to_addr)

    if not from_dom or not reply_to_dom:
        return None, []

    from_base = get_base_domain(from_dom)
    reply_to_base = get_base_domain(reply_to_dom)

    if from_base == reply_to_base:
        return None, []

    findings: List[ForensicFinding] = []

    # Check cache
    cache_key = f"{from_addr}->{reply_to_addr}"
    cached = get_cached_intel("REPLY_TO_INFRA", cache_key)
    if cached:
        reply_to_obj = ReplyToInfrastructure(**cached)
        findings.append(ForensicFinding(
            id="REPLY_TO_DOMAIN_MISMATCH",
            severity="HIGH",
            category="IDENTITY_SPOOFING",
            title="Reply-To Domain Divergence Detected",
            description=f"Replies are routed to an external domain ('{reply_to_dom}') different from sender domain ('{from_dom}').",
            technical_detail=f"From: {from_addr} | Reply-To: {reply_to_addr}",
            recommendation="Verify recipient authenticity before replying. Common in Business Email Compromise (BEC)."
        ))
        return reply_to_obj, findings

    # Resolve MX and WHOIS on the Reply-To domain
    mx_infra, mx_findings = resolve_mx_infra(reply_to_dom)
    whois_intel, whois_findings = resolve_whois_intel(reply_to_dom)

    reply_to_obj = ReplyToInfrastructure(
        from_address=from_addr,
        reply_to_address=reply_to_addr,
        from_domain=from_dom,
        reply_to_domain=reply_to_dom,
        reply_to_mismatch=True,
        mx_infra=mx_infra,
        whois_intel=whois_intel
    )

    set_cached_intel("REPLY_TO_INFRA", cache_key, reply_to_obj.model_dump())

    findings.append(ForensicFinding(
        id="REPLY_TO_DOMAIN_MISMATCH",
        severity="HIGH",
        category="IDENTITY_SPOOFING",
        title="Reply-To Domain Divergence Detected",
        description=f"Replies are routed to an external domain ('{reply_to_dom}') different from sender domain ('{from_dom}').",
        technical_detail=f"From: {from_addr} | Reply-To: {reply_to_addr}",
        recommendation="Verify recipient authenticity before replying. Common in Business Email Compromise (BEC)."
    ))

    findings.extend(mx_findings)
    findings.extend(whois_findings)
    return reply_to_obj, findings

# =========================================================================
# 5. Composite Infrastructure Evidence Orchestration
# =========================================================================

def gather_alternative_infrastructure_evidence(
    origin_status: str,
    from_address: Optional[str],
    reply_to_address: Optional[str],
    urls: List[str]
) -> Tuple[Optional[InfrastructureEvidence], List[ForensicFinding]]:
    """
    Main orchestration entry point for Task 2.
    - If origin_status is PROVIDER_RELAY or ANONYMIZED: gathers link, MX, WHOIS, and Reply-To evidence.
    - If origin_status is ORIGIN_FOUND: gathers link and Reply-To evidence (skips redundant MX).
    - Computes attribution confidence strictly capped at 40% when sender IP is unavailable.
    """
    findings: List[ForensicFinding] = []
    corroborating_signals: List[str] = []

    from_domain = extract_domain(from_address) if from_address else None

    # 1. Resolve Link Infrastructure
    link_results, link_findings = resolve_link_infra(urls)
    findings.extend(link_findings)

    # 2. Resolve Reply-To Infrastructure
    reply_to_res, reply_findings = resolve_reply_to_infra(from_address, reply_to_address)
    findings.extend(reply_findings)

    mx_res = None
    whois_res = None

    if origin_status in ["PROVIDER_RELAY", "ANONYMIZED"]:
        # When sender real IP is unavailable, gather full infrastructure evidence
        if from_domain:
            mx_res, mx_findings = resolve_mx_infra(from_domain)
            findings.extend(mx_findings)
            whois_res, whois_findings = resolve_whois_intel(from_domain)
            findings.extend(whois_findings)

    # 3. Calculate Corroborating Signal Count & Confidence
    confidence_score = 0.10

    if whois_res and whois_res.is_newly_registered:
        corroborating_signals.append("Sender domain is newly registered (< 30 days)")
        confidence_score += 0.15

    if reply_to_res and reply_to_res.reply_to_mismatch:
        corroborating_signals.append("Reply-To communication diversion to external domain")
        confidence_score += 0.20

    has_susp_link_hosting = any(l.is_suspicious_hosting for l in link_results)
    if has_susp_link_hosting:
        corroborating_signals.append("Email links hosted on bulletproof / commercial VPS infrastructure")
        confidence_score += 0.15

    has_link_mismatch = any(l.domain != from_domain for l in link_results if from_domain)
    if has_link_mismatch:
        corroborating_signals.append("Link destinations diverge from sender organization domain")
        confidence_score += 0.10

    has_shortener = any(l.is_shortener for l in link_results)
    if has_shortener:
        corroborating_signals.append("URL shortener used to conceal link destination")
        confidence_score += 0.10

    # Strict Cap Rule: Confidence is capped at 40% when sender IP itself is unavailable
    if origin_status in ["PROVIDER_RELAY", "ANONYMIZED"]:
        confidence_score = min(0.40, confidence_score)
        conf_level = "LOW" if confidence_score <= 0.25 else "MEDIUM"
        notes = "Alternative infrastructure evidence evaluated because sender client IP is concealed by provider."
    else:
        confidence_score = min(0.90, confidence_score)
        conf_level = "HIGH" if confidence_score >= 0.70 else ("MEDIUM" if confidence_score >= 0.40 else "LOW")
        notes = "Corroborating link and routing infrastructure analyzed alongside direct origin IP."

    evidence = InfrastructureEvidence(
        links=link_results,
        mx_infra=mx_res,
        whois_intel=whois_res,
        reply_to_infra=reply_to_res,
        corroborating_signals=corroborating_signals,
        confidence_score=round(confidence_score, 2),
        confidence_level=conf_level,
        notes=notes
    )

    return evidence, findings
