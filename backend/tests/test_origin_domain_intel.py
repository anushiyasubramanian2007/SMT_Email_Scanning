import pytest
from app.forensics.origin_tracer import trace_origin_ip, enrich_ip_geolocation, analyze_origin_and_geolocation
from app.forensics.domain_intel import detect_lookalike_domain, query_dns_records, analyze_domain_intel
from app.forensics.header_analyzer import analyze_email_headers
from app.schemas.forensic_schemas import RelayHop
from app.database.db import SessionLocal, GeoIPCache, DomainIntelCache

# =====================================================================
# 1. ORIGIN TRACING & RELIABLE IP EXTRACTION
# =====================================================================

def test_origin_tracer_skips_private_hops():
    """Verify origin tracer skips private LAN/loopback hops and selects earliest public IP."""
    hops = [
        RelayHop(
            hop_number=1,
            from_host="laptop.internal.lan",
            from_ip="192.168.1.105",
            by_host="corp-exchange.lan",
            protocol="SMTP",
            timestamp="2026-09-24T10:00:00+00:00",
            is_private_ip=True,
            raw="Received: from laptop.internal.lan (192.168.1.105) by corp-exchange.lan"
        ),
        RelayHop(
            hop_number=2,
            from_host="corp-exchange.lan",
            from_ip="10.0.0.1",
            by_host="mail-edge.company.com",
            protocol="SMTP",
            timestamp="2026-09-24T10:00:15+00:00",
            is_private_ip=True,
            raw="Received: from corp-exchange.lan (10.0.0.1) by mail-edge.company.com"
        ),
        RelayHop(
            hop_number=3,
            from_host="mail-edge.company.com",
            from_ip="198.51.100.55",
            by_host="mx.recipient.com",
            protocol="ESMTPS",
            timestamp="2026-09-24T10:00:30+00:00",
            is_private_ip=False,
            raw="Received: from mail-edge.company.com (198.51.100.55) by mx.recipient.com with ESMTPS"
        )
    ]

    origin_ip, score, justification, hop_num, mta = trace_origin_ip(hops)
    assert origin_ip == "198.51.100.55"
    assert hop_num == 3
    assert score >= 0.90
    assert "mx.recipient.com" in justification

def test_origin_tracer_with_x_originating_ip():
    """Verify X-Originating-IP takes precedence when a public client IP is recorded."""
    hops = [
        RelayHop(
            hop_number=1,
            from_host="mail-relay.net",
            from_ip="203.0.113.1",
            by_host="mx.target.com",
            protocol="ESMTPS",
            raw="Received: from mail-relay.net"
        )
    ]
    origin_ip, score, justification, hop_num, mta = trace_origin_ip(
        hops, x_originating_ip="198.51.100.99"
    )
    assert origin_ip == "198.51.100.99"
    assert score == 0.95
    assert "X-Originating-IP" in justification

# =====================================================================
# 2. TOR, VPN, AND CLOUD INFRASTRUCTURE DETECTION
# =====================================================================

def test_tor_exit_node_detection():
    """Verify Tor exit node IP is detected, tagged, and flagged with CRITICAL finding."""
    tor_ip = "185.220.101.5"
    geo_intel = enrich_ip_geolocation(tor_ip)
    assert geo_intel.is_tor is True
    assert "TOR_EXIT_NODE" in geo_intel.threat_labels

    hops = [RelayHop(hop_number=1, from_ip=tor_ip, by_host="mx.google.com", protocol="ESMTPS", raw="Received: from tor")]
    trace_res, findings = analyze_origin_and_geolocation(hops)
    assert trace_res.origin_ip == tor_ip
    assert any(f.id == "TOR_EXIT_NODE_ORIGIN" for f in findings)
    tor_finding = next(f for f in findings if f.id == "TOR_EXIT_NODE_ORIGIN")
    assert tor_finding.severity == "CRITICAL"

def test_vpn_hosting_classification():
    """Verify commercial hosting/datacenter IP is classified appropriately."""
    # Pre-seed SQLite cache with a known hosting IP to guarantee deterministic testing offline
    test_ip = "185.190.140.1"
    db = SessionLocal()
    cache_entry = GeoIPCache(
        ip=test_ip,
        country="United Kingdom",
        country_code="GB",
        region="London",
        city="London",
        latitude=51.5074,
        longitude=-0.1278,
        asn="AS62240",
        isp="M247 Ltd Hosting",
        org="M247 European Datacenter",
        is_tor=False,
        is_vpn_proxy=True,
        is_cloud=False
    )
    db.merge(cache_entry)
    db.commit()
    db.close()

    geo_intel = enrich_ip_geolocation(test_ip)
    assert geo_intel.is_vpn_proxy is True
    assert "HOSTING_OR_VPN_PROVIDER" in geo_intel.threat_labels

# =====================================================================
# 3. LOOKALIKE & HOMOGLYPH DOMAIN DETECTION
# =====================================================================

def test_lookalike_levenshtein_detection():
    """Test Levenshtein typo-squatting detection on homoglyphs and confusable characters."""
    # Leetspeak 1 instead of l
    is_lookalike, brand, technique, sim = detect_lookalike_domain("paypa1.com")
    assert is_lookalike is True
    assert brand == "Paypal"

    # Number 0 instead of o
    is_lookalike, brand, technique, sim = detect_lookalike_domain("micros0ft.com")
    assert is_lookalike is True
    assert brand == "Microsoft"

    # Deceptive hyphenated brand keyword squatting
    is_lookalike, brand, technique, sim = detect_lookalike_domain("paypal-security-recovery.org")
    assert is_lookalike is True
    assert brand == "Paypal"

    # Official legitimate brand domain should NOT be flagged
    is_lookalike, brand, technique, sim = detect_lookalike_domain("paypal.com")
    assert is_lookalike is False

    # Neutral benign company domain should NOT be flagged
    is_lookalike, brand, technique, sim = detect_lookalike_domain("acmecorp-internal.com")
    assert is_lookalike is False

# =====================================================================
# 4. DNS RECORD ENRICHMENT & OFFLINE RESILIENCE
# =====================================================================

def test_dns_records_graceful_fallback():
    """Verify DNS querying completes quickly and returns clean data on non-existent domain."""
    mx, spf, dmarc = query_dns_records("nonexistent-threat-domain-test-xyz.invalid", timeout=1.0)
    assert isinstance(mx, list)
    assert len(mx) == 0
    assert spf is None
    assert dmarc is None

def test_sqlite_caching_domain_intel():
    """Verify DomainIntelCache successfully persists and avoids redundant network lookups."""
    test_domain = "cached-threat-test.com"
    db = SessionLocal()
    cache_entry = DomainIntelCache(
        domain=test_domain,
        domain_age_days=12,
        registrar="NameCheap",
        is_nrd=True,
        mx_records='["mail.cached-threat-test.com"]',
        spf_record="v=spf1 ~all",
        dmarc_record="v=DMARC1; p=none;"
    )
    db.merge(cache_entry)
    db.commit()
    db.close()

    intel_res, findings = analyze_domain_intel(test_domain)
    assert intel_res.domain == test_domain
    assert intel_res.domain_age_days == 12
    assert intel_res.is_newly_registered is True
    assert any(f.id == "NEWLY_REGISTERED_DOMAIN" for f in findings)

# =====================================================================
# 5. INTEGRATION IN FORENSIC RESPONSE (PHASE 2 DATA IN POST /api/forensics/analyze)
# =====================================================================

def test_forensics_endpoint_phase2_enrichment(client, auth_headers, load_fixture):
    """Verify POST /api/forensics/analyze contains origin_trace and domain_intel objects."""
    eml_bytes = load_fixture("tor_origin.eml")
    response = client.post(
        "/api/forensics/analyze",
        headers=auth_headers,
        files={"file": ("tor_origin.eml", eml_bytes, "message/rfc822")}
    )
    assert response.status_code == 200
    data = response.json()

    # Check Phase 2 fields in JSON response
    assert "origin_trace" in data
    assert data["origin_trace"]["origin_ip"] == "185.220.101.5"
    assert data["origin_trace"]["geolocation"]["is_tor"] is True
    assert "TOR_EXIT_NODE" in data["origin_trace"]["geolocation"]["threat_labels"]

    assert "domain_intel" in data
    assert data["domain_intel"]["domain"] == "onionmail.org"

def test_lookalike_domain_forensic_response(client, auth_headers, load_fixture):
    """Verify lookalike domain fixture produces lookalike intel in response."""
    eml_bytes = load_fixture("lookalike_domain.eml")
    response = client.post(
        "/api/forensics/analyze",
        headers=auth_headers,
        files={"file": ("lookalike.eml", eml_bytes, "message/rfc822")}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["domain_intel"]["is_lookalike"] is True
    assert data["domain_intel"]["lookalike_target"] == "Paypal"
    assert any(f["id"] == "LOOKALIKE_BRAND_DOMAIN" for f in data["findings"])

# =====================================================================
# 6. TASK 1 SPECIFICATION TESTS: 3 STATUSES & PROVIDER RELAY SKIPPING
# =====================================================================

def test_provider_relay_skipping_and_status():
    """Verify Google relay IP (209.85.220.41) produces PROVIDER_RELAY with stripped lat/lon and <=40% confidence."""
    # Pre-seed cache to ensure test works offline without network dependencies
    db = SessionLocal()
    db.merge(GeoIPCache(
        ip="209.85.220.41",
        country="United States",
        country_code="US",
        region="California",
        city="Mountain View",
        latitude=37.3861,
        longitude=-122.084,
        asn="AS15169",
        isp="Google LLC",
        org="Google LLC",
        is_tor=False,
        is_vpn_proxy=False,
        is_cloud=True
    ))
    db.commit()
    db.close()

    hops = [
        RelayHop(
            hop_number=1,
            from_host="mail-sor-f41.google.com",
            from_ip="209.85.220.41",
            by_host="mx.recipient.com",
            protocol="ESMTPS",
            raw="Received: from mail-sor-f41.google.com ([209.85.220.41]) by mx.recipient.com with ESMTPS"
        )
    ]
    trace_res, findings = analyze_origin_and_geolocation(hops)

    assert trace_res.origin_status == "PROVIDER_RELAY"
    assert trace_res.provider_name == "Google"
    assert "Sent through Google. The provider does not expose the sender's real IP." in trace_res.status_message
    assert trace_res.confidence_level == "LOW"
    assert trace_res.reliability_score <= 0.40
    # Omit lat/lon for provider relay
    assert trace_res.geolocation.latitude is None
    assert trace_res.geolocation.longitude is None
    assert trace_res.location_unreliable is True
    assert any(f.id == "PROVIDER_RELAY_ORIGIN" for f in findings)

def test_token_validation_discards_internal_ids():
    """Verify validate_ip_token discards non-IP strings and Gmail internal 2002: IDs."""
    from app.forensics.header_analyzer import validate_ip_token
    assert validate_ip_token("2002:aa7:c4f5:0:b0:1234:5678:9abc") is None
    assert validate_ip_token("not-an-ip-address") is None
    assert validate_ip_token("999.999.999.999") is None
    assert validate_ip_token("209.85.220.41") == "209.85.220.41"
    assert validate_ip_token("[2001:4860:4860::8888]") == "2001:4860:4860::8888"

def test_anonymized_status_on_tor_origin():
    """Verify Tor exit node IP produces ANONYMIZED status with location marked unreliable."""
    hops = [
        RelayHop(
            hop_number=1,
            from_host="tor-node.exit",
            from_ip="185.220.101.5",
            by_host="mx.recipient.com",
            protocol="ESMTPS",
            raw="Received: from tor-node.exit ([185.220.101.5]) by mx.recipient.com"
        )
    ]
    trace_res, findings = analyze_origin_and_geolocation(hops)
    assert trace_res.origin_status == "ANONYMIZED"
    assert trace_res.location_unreliable is True
    assert "Tor exit node" in trace_res.status_message
    assert any(f.id == "TOR_EXIT_NODE_ORIGIN" for f in findings)

def test_origin_found_on_direct_public_ip():
    """Verify non-provider public IP produces ORIGIN_FOUND status with coordinates."""
    hops = [
        RelayHop(
            hop_number=1,
            from_host="mail.customcorp.net",
            from_ip="198.51.100.22",
            by_host="mx.recipient.com",
            protocol="ESMTPS",
            raw="Received: from mail.customcorp.net ([198.51.100.22]) by mx.recipient.com"
        )
    ]
    trace_res, findings = analyze_origin_and_geolocation(hops)
    assert trace_res.origin_status == "ORIGIN_FOUND"
    assert trace_res.origin_ip == "198.51.100.22"
    assert trace_res.confidence_level in ["MEDIUM", "HIGH"]
    assert "non-provider" in trace_res.status_message.lower() or "origin infrastructure" in trace_res.status_message.lower()

def test_google_relay_offline_detection():
    """Verify Google relay IP (209.85.220.41) produces PROVIDER_RELAY even without cache."""
    # Ensure IP is not in cache
    db = SessionLocal()
    db.query(GeoIPCache).filter(GeoIPCache.ip == "209.85.220.41").delete()
    db.commit()
    db.close()

    hops = [
        RelayHop(
            hop_number=1,
            from_host="mail-sor-f41.google.com",
            from_ip="209.85.220.41",
            by_host="mx.recipient.com",
            protocol="ESMTPS",
            raw="Received: from mail-sor-f41.google.com ([209.85.220.41]) by mx.recipient.com with ESMTPS"
        )
    ]
    trace_res, findings = analyze_origin_and_geolocation(hops)
    assert trace_res.origin_status == "PROVIDER_RELAY"
    assert trace_res.provider_name == "Google"
    assert trace_res.reliability_score <= 0.40
    assert trace_res.confidence_level == "LOW"
    assert trace_res.geolocation.latitude is None
    assert trace_res.geolocation.longitude is None

def test_attribution_for_provider_relay_never_benign_origin():
    """Verify attribution engine never reports BENIGN_ORIGIN with high confidence for provider relay."""
    from app.correlation.attribution import attribute_threat_origin
    from app.schemas.forensic_schemas import EmailEnvelope, AuthenticationForensics, AuthStatus, FraudScoreBreakdown, FactorScore

    hops = [
        RelayHop(
            hop_number=1,
            from_host="mail-sor-f41.google.com",
            from_ip="209.85.220.41",
            by_host="mx.recipient.com",
            protocol="ESMTPS",
            raw="Received: from mail-sor-f41.google.com ([209.85.220.41]) by mx.recipient.com with ESMTPS"
        )
    ]
    trace_res, findings = analyze_origin_and_geolocation(hops)

    envelope = EmailEnvelope(
        from_header="Google Alert <alert@google.com>",
        from_address="alert@google.com",
        from_domain="google.com"
    )
    auth = AuthenticationForensics(
        spf=AuthStatus(verdict="pass", domain="google.com"),
        dkim=AuthStatus(verdict="pass", domain="google.com", aligned=True),
        dmarc=AuthStatus(verdict="pass", domain="google.com")
    )
    dummy_factor = FactorScore(factor_name="Test", score=2.0, weight=0.2, max_score=20.0, status="CLEAN", explanation="Clean")
    fraud_score = FraudScoreBreakdown(
        overall_score=10,
        risk_tier="LOW",
        predicted_category="legitimate",
        primary_risk_driver="None",
        nlp_linguistic_factor=dummy_factor,
        header_transport_factor=dummy_factor,
        authentication_factor=dummy_factor,
        domain_intel_factor=dummy_factor,
        ip_reputation_factor=dummy_factor
    )

    attr = attribute_threat_origin(
        envelope=envelope,
        auth=auth,
        findings=findings,
        origin_trace=trace_res,
        fraud_score=fraud_score
    )

    assert attr.archetype == "PROVIDER_RELAY"
    assert attr.confidence <= 0.40
    assert "BENIGN_ORIGIN" not in attr.archetype
    assert "Origin cannot be determined from headers" in attr.explanation or "scrubs" in attr.explanation

def test_timezone_aware_hop_delays():
    """Verify hop delay parsing correctly normalizes timezones and calculates delta."""
    raw_email = (
        b"From: sender@example.com\r\n"
        b"To: recipient@example.com\r\n"
        b"Subject: Timezone Test\r\n"
        b"Received: from mx2.target.com (mx2.target.com [198.51.100.1]) by final.local with SMTP; Fri, 25 Sep 2026 15:30:10 +0530\r\n"
        b"Received: from mta1.source.com (mta1.source.com [198.51.100.2]) by mx2.target.com with ESMTP; Fri, 25 Sep 2026 10:00:00 +0000\r\n"
        b"\r\n"
        b"Test body"
    )
    # Hop 1 is mta1 (earliest, 10:00:00 UTC)
    # Hop 2 is mx2 (15:30:10 +0530, which is 10:00:10 UTC)
    # The elapsed time should be exactly 10.0 seconds!
    result = analyze_email_headers(raw_email)
    assert len(result.relay_path) == 2
    assert result.relay_path[1].delay_seconds == 10.0
    assert result.relay_path[1].delay_flag == "NORMAL"

def test_hop_delay_flag_inversion_and_extreme():
    """Verify time inversion and extreme delays set appropriate flags."""
    raw_email = (
        b"From: sender@example.com\r\n"
        b"To: recipient@example.com\r\n"
        b"Subject: Inversion Test\r\n"
        b"Received: from hop2.net by hop3.net; Fri, 25 Sep 2026 10:00:00 +0000\r\n"
        b"Received: from hop1.net by hop2.net; Fri, 25 Sep 2026 11:00:00 +0000\r\n"
        b"\r\n"
        b"Test body"
    )
    # Reversed: Hop 1 is 11:00:00, Hop 2 is 10:00:00 -> -3600 seconds delay
    result = analyze_email_headers(raw_email)
    assert result.relay_path[1].delay_seconds == -3600.0
    assert result.relay_path[1].delay_flag == "TIME_INVERSION"
    assert any(f.id == "RECEIVED_CHAIN_TIME_INVERSION" for f in result.findings)

