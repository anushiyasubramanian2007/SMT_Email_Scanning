import os
import pytest
from app.forensics.header_analyzer import analyze_email_headers
from app.correlation.attribution import attribute_threat_origin
from app.correlation.graph import build_case_graph, build_single_forensic_graph
from app.correlation.engine import (
    create_case,
    list_cases,
    get_case_by_id,
    record_and_correlate_email
)
from app.database.db import get_db, Case, CaseEmail, ThreatIndicator, ThreatCampaign

# =====================================================================
# 1. ORIGIN ATTRIBUTION CLASSIFIER TESTS
# =====================================================================

def test_attribution_compromised_account(load_fixture):
    """Verify BEC invoice fraud attributes to COMPROMISED_ACCOUNT."""
    eml = load_fixture("bec_invoice_fraud.eml")
    result = analyze_email_headers(eml)
    assert result.attribution is not None
    assert result.attribution.archetype == "COMPROMISED_ACCOUNT"
    assert result.attribution.confidence >= 0.85
    assert "Compromised" in result.attribution.title
    assert any("Reply-To" in ev for ev in result.attribution.evidence)

def test_attribution_anonymized_tor_infrastructure(load_fixture):
    """Verify Tor origin email attributes to ANONYMIZED_INFRASTRUCTURE."""
    eml = load_fixture("tor_origin.eml")
    result = analyze_email_headers(eml)
    assert result.attribution is not None
    assert result.attribution.archetype == "ANONYMIZED_INFRASTRUCTURE"
    assert result.attribution.confidence >= 0.90
    assert "Tor" in result.attribution.title

def test_attribution_spoofed_lookalike_identity(load_fixture):
    """Verify lookalike domain email attributes to SPOOFED_IDENTITY."""
    eml = load_fixture("lookalike_domain.eml")
    result = analyze_email_headers(eml)
    assert result.attribution is not None
    assert result.attribution.archetype == "SPOOFED_IDENTITY"
    assert result.attribution.confidence >= 0.90

def test_attribution_unauthenticated_forged_relay(load_fixture):
    """Verify time-inverted headers attribute to UNAUTHENTICATED_RELAY."""
    eml = load_fixture("forged_received_chain.eml")
    result = analyze_email_headers(eml)
    assert result.attribution is not None
    assert result.attribution.archetype == "UNAUTHENTICATED_RELAY"

def test_attribution_benign_origin(load_fixture):
    """Verify clean business email attributes to BENIGN_ORIGIN."""
    eml = load_fixture("legitimate_email.eml")
    result = analyze_email_headers(eml)
    assert result.attribution is not None
    assert result.attribution.archetype == "BENIGN_ORIGIN"
    assert result.attribution.confidence >= 0.90

# =====================================================================
# 2. IOC EXTRACTION & THREAT GRAPH TESTS
# =====================================================================

def test_single_email_graph_generation(load_fixture):
    """Verify D3-compatible threat graph generated from a single email."""
    eml = load_fixture("bec_invoice_fraud.eml")
    result = analyze_email_headers(eml)
    graph = build_single_forensic_graph(result)

    assert len(graph.nodes) >= 4  # email, sender, domain, reply-to, origin ip, geo, asn, attribution
    assert len(graph.edges) >= 3
    node_types = {n.type for n in graph.nodes}
    assert "email" in node_types
    assert "sender" in node_types
    assert "domain" in node_types
    assert graph.stats["total_nodes"] == len(graph.nodes)
    assert graph.stats["total_edges"] == len(graph.edges)

def test_preview_forensic_graph_endpoint(client, auth_headers, load_fixture):
    """Verify POST /api/forensics/graph-preview returns D3 graph."""
    eml = load_fixture("credential_harvesting.eml")
    resp = client.post(
        "/api/forensics/graph-preview",
        files={"file": ("credential_harvesting.eml", eml, "message/rfc822")},
        headers=auth_headers
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "nodes" in data
    assert "edges" in data
    assert "stats" in data
    assert len(data["nodes"]) > 0

# =====================================================================
# 3. CASE MANAGEMENT & CORRELATION INTEGRATION TESTS
# =====================================================================

def test_case_lifecycle_crud(client, auth_headers):
    """Verify full CRUD lifecycle for investigation cases."""
    # 1. Create Case
    create_payload = {
        "title": "Operation GhostWire: Q3 BEC Investigation",
        "severity": "CRITICAL",
        "description": "Cross-departmental investigation into wire transfer diversion attempts",
        "tags": "bec,finance,wire-fraud",
        "assigned_to": "Senior SOC Lead"
    }
    create_resp = client.post("/api/cases", json=create_payload, headers=auth_headers)
    assert create_resp.status_code == 200
    case_data = create_resp.json()
    case_id = case_data["id"]
    assert case_id.startswith("CASE-")
    assert case_data["title"] == create_payload["title"]
    assert case_data["status"] == "OPEN"
    assert case_data["email_count"] == 0

    # 2. Get Case
    get_resp = client.get(f"/api/cases/{case_id}", headers=auth_headers)
    assert get_resp.status_code == 200
    assert get_resp.json()["id"] == case_id

    # 3. Update Case Status
    patch_payload = {"status": "INVESTIGATING", "severity": "HIGH"}
    patch_resp = client.patch(f"/api/cases/{case_id}", json=patch_payload, headers=auth_headers)
    assert patch_resp.status_code == 200
    assert patch_resp.json()["status"] == "INVESTIGATING"
    assert patch_resp.json()["severity"] == "HIGH"

    # 4. List Cases
    list_resp = client.get("/api/cases", headers=auth_headers)
    assert list_resp.status_code == 200
    assert any(c["id"] == case_id for c in list_resp.json())

def test_email_ingestion_correlation_and_case_association(client, auth_headers, load_fixture):
    """Verify email ingestion correlates IOCs, generates campaign, and links to case."""
    eml = load_fixture("bec_invoice_fraud.eml")
    
    # 1. Ingest email via forensic endpoint
    ingest_resp = client.post(
        "/api/forensics/analyze",
        files={"file": ("bec_invoice_fraud.eml", eml, "message/rfc822")},
        headers=auth_headers
    )
    assert ingest_resp.status_code == 200
    email_data = ingest_resp.json()
    assert email_data["attribution"] is not None

    # 2. Check Threat Indicators populated
    indicators_resp = client.get("/api/indicators", headers=auth_headers)
    assert indicators_resp.status_code == 200
    iocs = indicators_resp.json()
    assert len(iocs) > 0
    ioc_values = [i["value"].lower() for i in iocs]
    assert "enterprise-corp.com" in ioc_values or "ceo.exec.emergency@gmail.com" in ioc_values

    # 3. Create Case and Associate Email
    case_resp = client.post(
        "/api/cases",
        json={"title": "Targeted BEC Case #102", "severity": "HIGH"},
        headers=auth_headers
    )
    case_id = case_resp.json()["id"]

    # Query latest CaseEmail in DB
    db = next(get_db())
    latest_email = db.query(CaseEmail).order_by(CaseEmail.id.desc()).first()
    assert latest_email is not None

    add_resp = client.post(
        f"/api/cases/{case_id}/add-email?email_id={latest_email.id}",
        headers=auth_headers
    )
    assert add_resp.status_code == 200

    # 4. Verify Case Graph contains Case and Email nodes
    graph_resp = client.get(f"/api/cases/{case_id}/graph", headers=auth_headers)
    assert graph_resp.status_code == 200
    graph = graph_resp.json()
    assert len(graph["nodes"]) >= 2
    assert len(graph["edges"]) >= 1
    assert any(n["type"] == "case" for n in graph["nodes"])
    assert any(n["type"] == "email" for n in graph["nodes"])

def test_campaign_listing_endpoint(client, auth_headers):
    """Verify GET /api/campaigns endpoint returns active campaigns."""
    resp = client.get("/api/campaigns", headers=auth_headers)
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)
