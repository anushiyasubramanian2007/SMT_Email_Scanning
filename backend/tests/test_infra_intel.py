"""
PhishingGuard Forensics: Tests for Alternative Infrastructure Evidence (Task 2)
Verifies link infrastructure resolution, suspicious VPS/bulletproof ASN detection,
shortener expansion, raw IP URLs, homoglyphs, Reply-To discrepancy telemetry,
WHOIS domain age detection, and confidence ceilings.
"""

import pytest
from unittest.mock import patch, MagicMock
from app.forensics.infra_intel import (
    resolve_link_infra,
    resolve_mx_infra,
    resolve_whois_intel,
    resolve_reply_to_infra,
    gather_alternative_infrastructure_evidence,
    SUSPICIOUS_HOSTING_ASNS
)
from app.schemas.forensic_schemas import GeoIPIntel, MxInfrastructure, WhoisIntel
from app.forensics.header_analyzer import analyze_email_headers
from app.reports.generator import generate_forensic_pdf, generate_siem_json_bundle


# =========================================================================
# 1. LINK INFRASTRUCTURE & ANOMALY DETECTION TESTS
# =========================================================================

def test_link_infra_raw_ip_and_at_symbol():
    """Verify raw IP address and @ symbol obfuscation in URLs are detected."""
    urls = [
        "http://198.51.100.4/login.php",
        "https://portal.bank.com@malicious-redirect.com/verify"
    ]
    with patch("app.forensics.infra_intel.enrich_ip_geolocation") as mock_geo:
        mock_geo.return_value = GeoIPIntel(
            ip="198.51.100.4",
            asn="AS1234",
            isp="Test ISP",
            org="Test ISP",
            country="US"
        )
        results, findings = resolve_link_infra(urls)

    assert len(results) == 2
    raw_ip_link = next(r for r in results if "198.51.100.4" in r.url)
    assert raw_ip_link.is_raw_ip is True
    assert raw_ip_link.domain == "198.51.100.4"

    at_link = next(r for r in results if "@" in r.url)
    assert at_link.has_at_symbol is True


def test_link_infra_idn_homoglyph_detection():
    """Verify punycode / IDN homoglyphs are flagged."""
    urls = [
        "https://xn--pple-43d.com/support",
        "https://apple.com/iphone"
    ]
    with patch("app.forensics.infra_intel.socket.getaddrinfo", return_value=[(None, None, None, None, ("93.184.216.34", 0))]):
        with patch("app.forensics.infra_intel.enrich_ip_geolocation") as mock_geo:
            mock_geo.return_value = GeoIPIntel(
                ip="93.184.216.34",
                asn="AS15169",
                isp="Legit Host",
                org="Legit Host",
                country="US"
            )
            results, findings = resolve_link_infra(urls)

    puny_link = next(r for r in results if "xn--" in r.url)
    assert puny_link.is_idn_homoglyph is True

    clean_link = next(r for r in results if "apple.com" in r.url)
    assert clean_link.is_idn_homoglyph is False


def test_link_infra_shortener_detection():
    """Verify URL shorteners (bit.ly, tinyurl, etc.) are detected."""
    urls = ["https://bit.ly/3xPh1sh"]
    
    with patch("app.forensics.infra_intel.get_cached_intel", return_value=None):
        with patch("app.forensics.infra_intel.requests.head") as mock_head:
            mock_resp = MagicMock()
            mock_resp.headers = {"Location": "https://evil-credential-stealer.xyz/login"}
            mock_resp.status_code = 301
            mock_head.return_value = mock_resp

            with patch("app.forensics.infra_intel.socket.getaddrinfo", return_value=[(None, None, None, None, ("67.199.248.11", 0))]):
                with patch("app.forensics.infra_intel.enrich_ip_geolocation") as mock_geo:
                    mock_geo.return_value = GeoIPIntel(
                        ip="67.199.248.11",
                        asn="AS14618",
                        isp="Bitly",
                        org="Bitly",
                        country="US"
                    )
                    results, findings = resolve_link_infra(urls)

    assert len(results) == 1
    short_link = results[0]
    assert short_link.is_shortener is True
    assert short_link.expanded_url == "https://evil-credential-stealer.xyz/login"


def test_link_infra_suspicious_vps_hosting():
    """Verify hosting on known bulletproof / cheap VPS ASNs (Hetzner, OVH, DigitalOcean) is flagged."""
    urls = ["https://pay-secure-billing-portal.cc/invoice"]

    with patch("app.forensics.infra_intel.socket.getaddrinfo", return_value=[(None, None, None, None, ("95.216.14.22", 0))]):
        with patch("app.forensics.infra_intel.enrich_ip_geolocation") as mock_geo:
            mock_geo.return_value = GeoIPIntel(
                ip="95.216.14.22",
                asn="AS24940",
                isp="Hetzner Online GmbH",
                org="Hetzner Online GmbH",
                country="DE",
                city="Falkenstein"
            )
            results, findings = resolve_link_infra(urls)

    assert len(results) == 1
    assert results[0].is_suspicious_hosting is True
    assert results[0].asn == "AS24940"
    assert "Hetzner" in (results[0].hosting_provider or "")


# =========================================================================
# 2. WHOIS & DOMAIN TELEMETRY TESTS
# =========================================================================

def test_whois_intel_graceful_failure():
    """Verify WHOIS failures or privacy guard return available=False without exceptions."""
    with patch("app.forensics.infra_intel.whois.whois", side_effect=Exception("WHOIS server unreachable")):
        intel, findings = resolve_whois_intel("unreachable-whois-domain-xyz.com")
        assert intel is not None
        assert intel.available is False
        assert intel.creation_date is None
        assert intel.is_newly_registered is False


def test_whois_intel_newly_registered():
    """Verify domains younger than 30 days are flagged as newly registered."""
    from datetime import datetime, timedelta, timezone
    recent_date = datetime.now(timezone.utc) - timedelta(days=12)

    mock_record = MagicMock()
    mock_record.creation_date = recent_date
    mock_record.registrar = "NameCheap, Inc."
    mock_record.country = "IS"

    with patch("app.forensics.infra_intel.whois.whois", return_value=mock_record):
        intel, findings = resolve_whois_intel("new-phish-domain-brand.com")
        assert intel is not None
        assert intel.available is True
        assert intel.is_newly_registered is True
        assert intel.domain_age_days == 12
        assert intel.registrar == "NameCheap, Inc."


# =========================================================================
# 3. REPLY-TO DISCREPANCY & INFRASTRUCTURE TESTS
# =========================================================================

def test_reply_to_mismatch_resolution():
    """Verify From vs Reply-To mismatch triggers secondary resolution."""
    from_addr = "ceo@acme-corp.com"
    reply_to = "ceo.acme@gmail.com"

    mock_mx_obj = MxInfrastructure(
        domain="gmail.com",
        primary_mx="gmail-smtp-in.l.google.com",
        resolved_ip="142.250.27.27",
        isp="Google LLC",
        asn="AS15169"
    )
    mock_whois_obj = WhoisIntel(
        domain="gmail.com",
        available=True,
        creation_date="1997-09-15",
        domain_age_days=10000,
        is_newly_registered=False
    )

    with patch("app.forensics.infra_intel.resolve_mx_infra", return_value=(mock_mx_obj, [])):
        with patch("app.forensics.infra_intel.resolve_whois_intel", return_value=(mock_whois_obj, [])):
            reply_infra, findings = resolve_reply_to_infra(from_addr, reply_to)

    assert reply_infra is not None
    assert reply_infra.is_mismatch is True
    assert reply_infra.from_domain == "acme-corp.com"
    assert reply_infra.reply_to_domain == "gmail.com"


def test_reply_to_match_no_mismatch():
    """Verify identical domains return None (no mismatch)."""
    from_addr = "support@microsoft.com"
    reply_to = "helpdesk@microsoft.com"

    reply_infra, findings = resolve_reply_to_infra(from_addr, reply_to)
    assert reply_infra is None
    assert len(findings) == 0


# =========================================================================
# 4. GATHER EVIDENCE & CONFIDENCE CEILING TESTS
# =========================================================================

def test_gather_evidence_confidence_cap_for_provider_relay():
    """Verify confidence is capped at <= 40% when origin is PROVIDER_RELAY."""
    evidence, findings = gather_alternative_infrastructure_evidence(
        origin_status="PROVIDER_RELAY",
        from_address="alert@service-notice.com",
        reply_to_address=None,
        urls=["https://test-link.com"]
    )
    assert evidence.confidence_cap <= 0.40
    assert "sender client IP is concealed by provider" in (evidence.confidence_note or "")


def test_gather_evidence_confidence_for_origin_found():
    """Verify confidence ceiling when origin is ORIGIN_FOUND."""
    evidence, findings = gather_alternative_infrastructure_evidence(
        origin_status="ORIGIN_FOUND",
        from_address="user@company.com",
        reply_to_address=None,
        urls=[]
    )
    assert evidence.confidence_cap <= 0.90


# =========================================================================
# 5. FULL PIPELINE & EXPORT TESTS
# =========================================================================

def test_full_pipeline_with_alternative_infrastructure(load_fixture):
    """Verify full header analysis populates infrastructure_evidence and exports cleanly."""
    eml_bytes = load_fixture("bec_invoice_fraud.eml")
    result = analyze_email_headers(eml_bytes)

    assert result.infrastructure_evidence is not None
    # Reply-To in bec_invoice_fraud.eml is john.doe.enterprise2026@gmail.com while From is enterprise-corp.com
    assert result.infrastructure_evidence.reply_to is not None
    assert result.infrastructure_evidence.reply_to.is_mismatch is True

    # Check finding was appended
    finding_ids = {f.id for f in result.findings}
    assert "REPLY_TO_DOMAIN_MISMATCH" in finding_ids or "REPLY_TO_DIVERSION" in finding_ids

    # Check PDF export renders without error
    pdf_bytes = generate_forensic_pdf(result)
    assert len(pdf_bytes) > 1000
    assert pdf_bytes.startswith(b"%PDF")

    # Check SIEM bundle contains infrastructure_evidence
    siem = generate_siem_json_bundle(result)
    assert "infrastructure_evidence" in siem
    assert siem["infrastructure_evidence"] is not None
