import io
import pytest
from app.forensics.header_analyzer import analyze_email_headers

# =====================================================================
# 1. CORE ENGINE UNIT TESTS (8 RFC 5322 .EML SAMPLES)
# =====================================================================

def test_legitimate_email_forensics(load_fixture):
    """Test 1: Legitimate email with valid SPF/DKIM/DMARC pass and monotonic hops."""
    content = load_fixture("legitimate_email.eml")
    result = analyze_email_headers(content)

    assert result.summary.verdict == "LEGITIMATE"
    assert result.summary.risk_score < 25
    assert result.envelope.from_address == "sjenkins@company.com"
    assert result.envelope.from_domain == "company.com"
    assert result.envelope.return_path == "sjenkins@company.com"
    assert result.authentication.spf.verdict == "pass"
    assert result.authentication.dkim.verdict == "pass"
    assert result.authentication.dmarc.verdict == "pass"
    assert result.summary.critical_findings == 0
    assert len(result.relay_path) == 2
    assert result.relay_path[0].from_host is not None

def test_spoofed_sender_forensics(load_fixture):
    """Test 2: Display name brand impersonation and From vs Return-Path mismatch."""
    content = load_fixture("spoofed_sender.eml")
    result = analyze_email_headers(content)

    assert result.summary.verdict in ["IMPERSONATION", "PHISHING", "CRITICAL_FRAUD"]
    assert result.summary.risk_score >= 50
    finding_ids = [f.id for f in result.findings]
    assert "BRAND_IMPERSONATION_DISPLAY_NAME" in finding_ids
    assert "FROM_RETURN_PATH_MISMATCH" in finding_ids
    assert result.authentication.spf.verdict == "fail"

def test_spf_fail_forensics(load_fixture):
    """Test 3: Unauthorized relay server triggering SPF HardFail and DMARC fail."""
    content = load_fixture("spf_fail.eml")
    result = analyze_email_headers(content)

    finding_ids = [f.id for f in result.findings]
    assert "SPF_VERIFICATION_FAILED" in finding_ids
    assert "DMARC_POLICY_FAILED" in finding_ids
    assert result.authentication.spf.verdict == "fail"
    assert result.authentication.dmarc.verdict == "fail"
    assert result.summary.critical_findings >= 1

def test_bec_invoice_fraud_forensics(load_fixture):
    """Test 4: BEC / Invoice fraud with executive impersonation and Reply-To freemail diversion."""
    content = load_fixture("bec_invoice_fraud.eml")
    result = analyze_email_headers(content)

    finding_ids = [f.id for f in result.findings]
    assert "REPLY_TO_DIVERSION" in finding_ids
    
    # Verify severity is elevated to CRITICAL due to freemail diversion
    bec_finding = next(f for f in result.findings if f.id == "REPLY_TO_DIVERSION")
    assert bec_finding.severity == "CRITICAL"
    assert "gmail.com" in bec_finding.description
    assert result.summary.verdict in ["BEC_FRAUD", "CRITICAL_FRAUD", "PHISHING"]

def test_credential_harvesting_forensics(load_fixture):
    """Test 5: Phishing lure with display name email injection and unaligned DKIM."""
    content = load_fixture("credential_harvesting.eml")
    result = analyze_email_headers(content)

    finding_ids = [f.id for f in result.findings]
    assert "DISPLAY_NAME_EMAIL_SPOOFING" in finding_ids
    assert "DKIM_DOMAIN_UNALIGNED" in finding_ids
    assert result.summary.risk_score >= 50

def test_forged_received_chain_forensics(load_fixture):
    """Test 6: Chronological inversion in Received hops indicating forged relay headers."""
    content = load_fixture("forged_received_chain.eml")
    result = analyze_email_headers(content)

    finding_ids = [f.id for f in result.findings]
    assert "RECEIVED_CHAIN_TIME_INVERSION" in finding_ids
    assert any(h.delay_seconds is not None and h.delay_seconds < 0 for h in result.relay_path)

def test_tor_origin_relay_forensics(load_fixture):
    """Test 7: Email relayed through anonymized Tor exit hop."""
    content = load_fixture("tor_origin.eml")
    result = analyze_email_headers(content)

    assert len(result.relay_path) >= 1
    first_hop = result.relay_path[0]
    assert first_hop.from_ip == "185.220.101.5"
    assert result.envelope.from_address == "whistleblower@onionmail.org"

def test_lookalike_domain_forensics(load_fixture):
    """Test 8: Brand lookalike domain with brand spoofing and SPF softfail."""
    content = load_fixture("lookalike_domain.eml")
    result = analyze_email_headers(content)

    finding_ids = [f.id for f in result.findings]
    assert "BRAND_IMPERSONATION_DISPLAY_NAME" in finding_ids
    assert "SPF_VERIFICATION_SOFTFAIL" in finding_ids
    assert result.summary.verdict in ["IMPERSONATION", "SUSPICIOUS", "PHISHING", "CRITICAL_FRAUD"]

# =====================================================================
# 2. REST API ENDPOINT INTEGRATION & AUTHENTICATION TESTS
# =====================================================================

def test_forensics_endpoint_multipart_upload(client, auth_headers, load_fixture):
    """Verify POST /api/forensics/analyze with multipart .eml file upload."""
    eml_bytes = load_fixture("legitimate_email.eml")
    response = client.post(
        "/api/forensics/analyze",
        headers=auth_headers,
        files={"file": ("legitimate.eml", io.BytesIO(eml_bytes), "message/rfc822")}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["summary"]["verdict"] == "LEGITIMATE"
    assert len(data["sha256"]) == 64
    assert "relay_path" in data
    assert "envelope" in data

def test_forensics_endpoint_json_payload(client, auth_headers, load_fixture):
    """Verify POST /api/forensics/analyze with JSON raw_content string."""
    eml_text = load_fixture("spoofed_sender.eml").decode("utf-8")
    response = client.post(
        "/api/forensics/analyze",
        headers=auth_headers,
        json={"raw_content": eml_text}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["summary"]["verdict"] in ["IMPERSONATION", "PHISHING", "CRITICAL_FRAUD"]

    assert data["summary"]["risk_score"] > 30

def test_forensics_endpoint_unauthorized(client, load_fixture):
    """Verify POST /api/forensics/analyze blocks unauthenticated requests."""
    eml_bytes = load_fixture("legitimate_email.eml")
    response = client.post(
        "/api/forensics/analyze",
        files={"file": ("test.eml", io.BytesIO(eml_bytes), "message/rfc822")}
    )
    assert response.status_code == 401

def test_forensics_endpoint_invalid_key(client, load_fixture):
    """Verify POST /api/forensics/analyze blocks requests with invalid API key."""
    eml_bytes = load_fixture("legitimate_email.eml")
    response = client.post(
        "/api/forensics/analyze",
        headers={"X-API-Key": "completely-invalid-key-xyz"},
        files={"file": ("test.eml", io.BytesIO(eml_bytes), "message/rfc822")}
    )
    assert response.status_code == 401

def test_forensics_endpoint_bearer_token(client, load_fixture):
    """Verify POST /api/forensics/analyze supports Authorization: Bearer <key>."""
    from conftest import TEST_API_KEY
    eml_bytes = load_fixture("legitimate_email.eml")
    response = client.post(
        "/api/forensics/analyze",
        headers={"Authorization": f"Bearer {TEST_API_KEY}"},
        files={"file": ("test.eml", io.BytesIO(eml_bytes), "message/rfc822")}
    )
    assert response.status_code == 200

def test_forensics_endpoint_empty_payload(client, auth_headers):
    """Verify POST /api/forensics/analyze returns 400 for empty payload."""
    response = client.post(
        "/api/forensics/analyze",
        headers=auth_headers,
        json={"raw_content": ""}
    )
    assert response.status_code == 400

# =====================================================================
# 3. BACKWARDS COMPATIBILITY FOR EXISTING EXTENSION ENDPOINTS
# =====================================================================

def test_existing_health_endpoint(client):
    """Verify /api/health continues to respond correctly."""
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"

def test_existing_email_analysis_endpoint(client):
    """Verify /api/analyze/email continues to respond for Chrome extension."""
    payload = {
        "subject": "Team Meeting",
        "body": "Hi team, let's meet at 4 PM to discuss the roadmap.",
        "sender_email": "manager@company.com",
        "sender_name": "Manager",
        "links": [],
        "attachments": [],
        "is_authenticated": True
    }
    response = client.post("/api/analyze/email", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] in ["legitimate", "safe"]

def test_existing_url_analysis_endpoint(client):
    """Verify /api/analyze/url continues to respond for Chrome extension."""
    payload = {"url": "http://test-phish.com/login"}
    response = client.post("/api/analyze/url", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "phishing"

def test_existing_dashboard_stats_endpoint(client):
    """Verify /api/dashboard/stats continues to respond."""
    response = client.get("/api/dashboard/stats")
    assert response.status_code == 200
    data = response.json()
    assert "stats" in data
    assert "recent_activity" in data
