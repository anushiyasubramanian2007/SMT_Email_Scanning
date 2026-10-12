"""
PhishingGuard Forensics: Domain Intelligence Engine
WHOIS (domain age, registrar, NRD flag), DNS Records (MX, SPF, DMARC),
Lookalike / Homoglyph / Typo-squatting Detection (Levenshtein & Confusables), and SQLite Caching.
"""

import re
import json
from datetime import datetime, timezone
from typing import Optional, List, Dict, Tuple, Any

import dns.resolver

from app.database.db import SessionLocal, DomainIntelCache
from app.schemas.forensic_schemas import DomainIntelResult, ForensicFinding
from app.forensics.header_analyzer import get_base_domain

# Target high-value brands protected against lookalike typo-squatting
PROTECTED_BRANDS = [
    "paypal", "microsoft", "google", "apple", "amazon", "netflix",
    "chase", "bankofamerica", "wellsfargo", "citibank", "dhl", "fedex",
    "ups", "irs", "facebook", "instagram", "linkedin", "dropbox",
    "coinbase", "binance", "outlook", "office365", "walmart"
]

# Character confusable / homoglyph mapping for leetspeak detection
HOMOGLYPH_MAP = {
    '1': 'l', 'l': '1', 'i': '1',
    '0': 'o', 'o': '0',
    'v': 'u', 'u': 'v',
    'w': 'vv',
    '5': 's', 's': '5',
    '3': 'e', 'e': '3',
    '8': 'b',
    '@': 'a'
}

def levenshtein_distance(s1: str, s2: str) -> int:
    """Compute the minimum edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)

    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]

def normalize_homoglyphs(text: str) -> str:
    """Normalize common leetspeak character substitutions to canonical letters."""
    norm = text.lower()
    norm = norm.replace("rn", "m")
    norm = norm.replace("cl", "d")
    norm = norm.replace("vv", "w")
    res = []
    for ch in norm:
        res.append(HOMOGLYPH_MAP.get(ch, ch))
    return "".join(res)

def detect_lookalike_domain(domain: str) -> Tuple[bool, Optional[str], Optional[str], Optional[float]]:
    """
    Check if a domain is a lookalike / typo-squat of a protected brand.
    Returns: (is_lookalike, target_brand, technique, similarity_score)
    """
    if not domain:
        return False, None, None, None

    base_domain = get_base_domain(domain) or domain
    # Domain stem: strip TLD (e.g. "paypa1" from "paypa1.com" or "paypal-update" from "paypal-update.org")
    domain_stem = base_domain.split(".")[0].lower()

    # 1. Check for IDN Homograph attack (Punycode xn--)
    if domain.startswith("xn--") or ".xn--" in domain:
        return True, "Internationalized Domain (IDN)", "IDN Punycode Homograph", 0.90

    # 2. Tokenize domain stem into components (e.g. "paypa1-service" -> ["paypa1-service", "paypa1", "service"])
    tokens = [domain_stem]
    subparts = re.split(r'[-_]', domain_stem)
    for p in subparts:
        if len(p) >= 3 and p not in tokens:
            tokens.append(p)

    for brand in PROTECTED_BRANDS:
        # If domain is the official brand domain itself, it's not a lookalike
        if domain_stem == brand and base_domain in [f"{brand}.com", f"{brand}.org", f"{brand}.net", f"{brand}.co.uk"]:
            continue

        # Check if brand is part of domain stem with deceptive suffix/prefix (e.g., "paypal-security", "login-microsoft")
        if re.search(r'(^|[-_])' + re.escape(brand) + r'([-_]|$)', domain_stem):
            return True, brand.title(), "Deceptive Brand Keyword Squatting", 0.85

        for tok in tokens:
            # Check Levenshtein distance
            dist = levenshtein_distance(tok, brand)
            if dist in [1, 2] and len(tok) >= 4 and abs(len(tok) - len(brand)) <= 2:
                similarity = round(1.0 - (dist / max(len(tok), len(brand))), 2)
                return True, brand.title(), f"Levenshtein Typo-Squatting (Distance: {dist})", similarity

            # Check Homoglyph / Confusables normalized distance
            norm_tok = normalize_homoglyphs(tok)
            if norm_tok == brand:
                return True, brand.title(), "Character Homoglyph / Leetspeak Substitution", 0.95
            
            norm_dist = levenshtein_distance(norm_tok, brand)
            if norm_dist in [1, 2] and abs(len(norm_tok) - len(brand)) <= 2:
                similarity = round(1.0 - (norm_dist / max(len(norm_tok), len(brand))), 2)
                return True, brand.title(), "Homoglyph Typo-Squatting", similarity

    return False, None, None, None

def query_dns_records(domain: str, timeout: float = 2.0) -> Tuple[List[str], Optional[str], Optional[str]]:
    """
    Query MX, SPF (TXT on root), and DMARC (TXT on _dmarc) records using dnspython.
    Gracefully handles offline environments and timeouts.
    """
    mx_records: List[str] = []
    spf_record: Optional[str] = None
    dmarc_record: Optional[str] = None

    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout + 0.5

    # 1. MX Records
    try:
        mx_answers = resolver.resolve(domain, "MX")
        for rdata in mx_answers:
            mx_records.append(str(rdata.exchange).rstrip("."))
    except Exception:
        pass

    # 2. SPF Record (TXT records on domain starting with v=spf1)
    try:
        txt_answers = resolver.resolve(domain, "TXT")
        for rdata in txt_answers:
            txt_str = "".join([s.decode("utf-8", errors="ignore") for s in rdata.strings])
            if txt_str.lower().startswith("v=spf1"):
                spf_record = txt_str
                break
    except Exception:
        pass

    # 3. DMARC Record (TXT records on _dmarc.<domain>)
    try:
        dmarc_answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
        for rdata in dmarc_answers:
            txt_str = "".join([s.decode("utf-8", errors="ignore") for s in rdata.strings])
            if txt_str.lower().startswith("v=dmarc1"):
                dmarc_record = txt_str
                break
    except Exception:
        pass

    return mx_records, spf_record, dmarc_record

def query_whois_intel(domain: str, timeout: float = 3.0) -> Tuple[Optional[datetime], Optional[int], Optional[str], bool]:
    """
    Query WHOIS for creation date, domain age, registrar, and NRD flag.
    Gracefully falls back when offline or timed out.
    """
    try:
        import whois
        # Set socket timeout to prevent hangs
        w = whois.whois(domain)
        creation = w.creation_date
        # Some registrars return a list of dates
        if isinstance(creation, list):
            creation = creation[0]
        
        registrar = str(w.registrar or "") or None
        
        if creation and isinstance(creation, datetime):
            if creation.tzinfo is not None:
                creation = creation.astimezone(timezone.utc).replace(tzinfo=None)
            now = datetime.utcnow()
            age_days = (now - creation).days
            is_nrd = (age_days < 30) if age_days >= 0 else False
            return creation, age_days, registrar, is_nrd
    except Exception:
        pass

    return None, None, None, False

def analyze_domain_intel(domain: Optional[str]) -> Tuple[Optional[DomainIntelResult], List[ForensicFinding]]:
    """
    Main entry point for Phase 2 Domain Intelligence.
    Performs WHOIS age check, DNS records inspection, and lookalike detection.
    """
    if not domain:
        return None, []

    domain_clean = domain.strip().lower().strip(".")
    base_domain = get_base_domain(domain_clean) or domain_clean

    findings: List[ForensicFinding] = []

    # 1. Check SQLite Cache
    db = SessionLocal()
    cached = None
    try:
        cached = db.query(DomainIntelCache).filter(DomainIntelCache.domain == domain_clean).first()
    except Exception:
        pass
    finally:
        db.close()

    creation_dt = None
    age_days = None
    registrar = None
    is_nrd = False
    mx_records: List[str] = []
    spf_rec = None
    dmarc_rec = None

    if cached:
        creation_dt = cached.creation_date
        age_days = cached.domain_age_days
        registrar = cached.registrar
        is_nrd = cached.is_nrd
        if cached.mx_records:
            try:
                mx_records = json.loads(cached.mx_records)
            except Exception:
                pass
        spf_rec = cached.spf_record
        dmarc_rec = cached.dmarc_record
    else:
        # 2. Live Query with Fallbacks
        mx_records, spf_rec, dmarc_rec = query_dns_records(domain_clean)
        creation_dt, age_days, registrar, is_nrd = query_whois_intel(domain_clean)

        # Cache in SQLite
        db = SessionLocal()
        try:
            cache_entry = DomainIntelCache(
                domain=domain_clean,
                creation_date=creation_dt,
                domain_age_days=age_days,
                registrar=registrar,
                is_nrd=is_nrd,
                mx_records=json.dumps(mx_records),
                spf_record=spf_rec,
                dmarc_record=dmarc_rec,
                created_at=datetime.utcnow()
            )
            db.merge(cache_entry)
            db.commit()
        except Exception:
            db.rollback()
        finally:
            db.close()

    # 3. Lookalike Detection
    is_lookalike, target_brand, technique, sim_score = detect_lookalike_domain(domain_clean)

    if is_lookalike:
        findings.append(ForensicFinding(
            id="LOOKALIKE_BRAND_DOMAIN",
            severity="CRITICAL" if (sim_score and sim_score >= 0.85) else "HIGH",
            category="IDENTITY_SPOOFING",
            title=f"Brand Lookalike Domain Detected ({target_brand})",
            description=(
                f"Domain '{domain_clean}' appears to impersonate '{target_brand}'. "
                f"Technique: {technique}. Similarity confidence: {(sim_score or 0.85)*100:.0f}%."
            ),
            technical_detail=f"Target: {target_brand} | Domain: {domain_clean} | Method: {technique}",
            recommendation="Block domain immediately. High probability of deceptive phishing/impersonation campaign."
        ))

    # 4. Newly Registered Domain (NRD) Evaluation
    if is_nrd or (age_days is not None and age_days < 30):
        findings.append(ForensicFinding(
            id="NEWLY_REGISTERED_DOMAIN",
            severity="HIGH",
            category="INFRASTRUCTURE",
            title="Newly Registered Domain (Age < 30 Days)",
            description=(
                f"Domain '{domain_clean}' was registered {age_days} days ago. "
                "Threat actors predominantly use newly registered domains to bypass reputation filtering."
            ),
            technical_detail=f"Creation Date: {creation_dt.isoformat() if creation_dt else 'Recent'} | Age: {age_days} days | Registrar: {registrar}",
            recommendation="Isolate communications from this newly registered infrastructure."
        ))
    elif age_days is not None and age_days < 90:
        findings.append(ForensicFinding(
            id="RECENTLY_REGISTERED_DOMAIN",
            severity="MEDIUM",
            category="INFRASTRUCTURE",
            title="Young Domain (Age < 90 Days)",
            description=f"Domain '{domain_clean}' is only {age_days} days old.",
            technical_detail=f"Age: {age_days} days | Registrar: {registrar}",
            recommendation="Scrutinize sender authenticity and link destinations."
        ))

    # 5. Missing MX records check (cannot receive mail)
    if not mx_records:
        findings.append(ForensicFinding(
            id="DOMAIN_NO_MX_RECORDS",
            severity="MEDIUM",
            category="PROTOCOL",
            title="Sender Domain Has No Mail Exchanger (MX) Records",
            description=f"Domain '{domain_clean}' does not advertise MX records to accept inbound email.",
            technical_detail="DNS query for MX yielded no records.",
            recommendation="Legitimate sending organizations typically maintain inbound MX records."
        ))

    intel_result = DomainIntelResult(
        domain=domain_clean,
        base_domain=base_domain,
        creation_date=creation_dt.isoformat() if creation_dt else None,
        domain_age_days=age_days,
        registrar=registrar,
        is_newly_registered=is_nrd,
        mx_records=mx_records,
        has_mx=bool(mx_records),
        spf_record=spf_rec,
        has_spf=bool(spf_rec),
        dmarc_record=dmarc_rec,
        has_dmarc=bool(dmarc_rec),
        is_lookalike=is_lookalike,
        lookalike_target=target_brand,
        lookalike_technique=technique,
        similarity_score=sim_score
    )

    return intel_result, findings
