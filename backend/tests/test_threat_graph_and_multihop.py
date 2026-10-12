import json
import pytest
from unittest.mock import patch
from app.forensics.header_analyzer import analyze_email_headers
from app.correlation.graph import build_single_forensic_graph, build_case_graph
from app.schemas.forensic_schemas import (
    ThreatGraphResponse,
    ForensicAnalysisResponse,
    RelayHop,
    EmailEnvelope,
    ForensicSummary,
    AuthenticationForensics,
    AuthStatus,
    FraudScoreBreakdown,
    FactorScore,
    OriginAttributionResult,
    InfrastructureEvidence,
    LinkInfrastructure,
    MxInfrastructure
)
from app.database.db import SessionLocal, Case, CaseEmail

# =====================================================================
# TASK 3 TEST SUITE: MULTI-HOP ATTRIBUTION & INTERACTIVE THREAT GRAPH
# =====================================================================

def test_multihop_enrichment_roles_and_geo(load_fixture):
    """Verify that multi-hop transmission chains assign proper roles and enrich geolocation/provider status."""
    # 1. Test private client submission in legitimate_email.eml
    content_legit = load_fixture("legitimate_email.eml")
    result_legit = analyze_email_headers(content_legit)

    assert len(result_legit.relay_path) == 2
    legit_hop1 = result_legit.relay_path[0]
    legit_hop2 = result_legit.relay_path[1]

    # Hop 1 has private IP 10.0.4.15 -> INTERNAL_CLIENT_SUBMISSION
    assert legit_hop1.hop_role == "INTERNAL_CLIENT_SUBMISSION"
    assert legit_hop1.is_private_ip is True

    # Hop 2 is the final destination hop -> INBOUND_GATEWAY
    assert legit_hop2.hop_role == "INBOUND_GATEWAY"

    # 2. Test multi-hop chain with private client hop in forged_received_chain.eml
    content_forged = load_fixture("forged_received_chain.eml")
    result_forged = analyze_email_headers(content_forged)

    assert len(result_forged.relay_path) == 3
    assert result_forged.relay_path[0].hop_role == "INTERNAL_CLIENT_SUBMISSION"
    assert result_forged.relay_path[1].hop_role == "INTERMEDIATE_RELAY"
    assert result_forged.relay_path[2].hop_role == "INBOUND_GATEWAY"

    # 3. Test multi-hop chain with public origin hop
    multi_hop_eml = (
        b"Received: from mx.target.com ([198.51.100.2]) by mailstore.target.com; Thu, 24 Sep 2026 12:02:00 +0000\r\n"
        b"Received: from relay.intermediate.net ([203.0.113.50]) by mx.target.com; Thu, 24 Sep 2026 12:01:00 +0000\r\n"
        b"Received: from origin.attacker.com ([45.33.32.156]) by relay.intermediate.net; Thu, 24 Sep 2026 12:00:00 +0000\r\n"
        b"From: scam@attacker.com\r\n"
        b"To: target@target.com\r\n"
        b"Subject: 3-Hop Public Chain\r\n\r\nPayload"
    )
    res_multi = analyze_email_headers(multi_hop_eml)
    assert len(res_multi.relay_path) == 3
    assert res_multi.relay_path[0].hop_role == "PROBABLE_ORIGIN_INFRASTRUCTURE"
    assert res_multi.relay_path[0].from_ip == "45.33.32.156"
    assert res_multi.relay_path[1].hop_role == "INTERMEDIATE_RELAY"
    assert res_multi.relay_path[2].hop_role == "INBOUND_GATEWAY"

def test_single_hop_role_assignment():
    """Verify role assignment when an email contains only a single hop."""
    # 1 hop with private IP
    single_private_eml = (
        b"Received: from client.local ([192.168.1.50]) by internal.local; Thu, 24 Sep 2026 12:00:00 +0000\r\n"
        b"From: test@example.com\r\n"
        b"To: target@example.com\r\n"
        b"Subject: Single Private Hop\r\n\r\nTest"
    )
    res_priv = analyze_email_headers(single_private_eml)
    assert len(res_priv.relay_path) == 1
    assert res_priv.relay_path[0].hop_role == "INTERNAL_CLIENT_SUBMISSION"
    assert res_priv.relay_path[0].country == "Private / Internal Network"

    # 1 hop with public IP
    single_public_eml = (
        b"Received: from mail.public.com ([198.51.100.10]) by mx.target.com; Thu, 24 Sep 2026 12:00:00 +0000\r\n"
        b"From: test@example.com\r\n"
        b"To: target@example.com\r\n"
        b"Subject: Single Public Hop\r\n\r\nTest"
    )
    res_pub = analyze_email_headers(single_public_eml)
    assert len(res_pub.relay_path) == 1
    assert res_pub.relay_path[0].hop_role == "INBOUND_GATEWAY"

def test_threat_graph_attached_to_analysis_response(load_fixture):
    """Verify that ForensicAnalysisResponse automatically attaches a complete threat_graph."""
    content = load_fixture("legitimate_email.eml")
    result = analyze_email_headers(content)

    assert result.threat_graph is not None
    assert isinstance(result.threat_graph, ThreatGraphResponse)
    assert len(result.threat_graph.nodes) > 0
    assert len(result.threat_graph.edges) > 0

    node_types = {n.type for n in result.threat_graph.nodes}
    assert "email" in node_types
    assert "sender" in node_types
    assert "domain" in node_types
    assert "hop" in node_types

    edge_relationships = {e.relationship for e in result.threat_graph.edges}
    assert "SENT_BY" in edge_relationships
    assert "HOSTED_ON" in edge_relationships
    assert "RELAYED_TO" in edge_relationships
    assert "INGRESS_TO" in edge_relationships

def test_time_inversion_graph_edges(load_fixture):
    """Verify that chronological delay inversion creates an INVERTED_RELAY_TO edge and critical hop node."""
    content = load_fixture("forged_received_chain.eml")
    result = analyze_email_headers(content)

    assert result.threat_graph is not None
    
    # Check that an edge has relationship INVERTED_RELAY_TO
    edge_rels = [e.relationship for e in result.threat_graph.edges]
    assert "INVERTED_RELAY_TO" in edge_rels

    # Check that inverted hop has CRITICAL risk
    hop_nodes = [n for n in result.threat_graph.nodes if n.type == "hop"]
    critical_hops = [h for h in hop_nodes if h.risk == "CRITICAL"]
    assert len(critical_hops) >= 1
    assert any(h.details.get("delay_flag") == "TIME_INVERSION" for h in critical_hops)

def test_infrastructure_evidence_in_threat_graph():
    """Verify that link expansion, hosting IPs, ASNs, and MX infrastructure appear in the threat graph."""
    dummy_factor = FactorScore(
        factor_name="Test",
        score=10.0,
        weight=0.2,
        max_score=20.0,
        status="WARNING",
        explanation="Test explanation"
    )

    res = ForensicAnalysisResponse(
        sha256="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        ingested_at="2026-09-25T12:00:00Z",
        summary=ForensicSummary(
            verdict="PHISHING",
            risk_score=85,
            confidence=0.92,
            total_findings=2,
            critical_findings=1,
            high_findings=1,
            medium_findings=0,
            low_findings=0,
            executive_summary="Critical Phishing detected with shortened URL redirect."
        ),
        fraud_score=FraudScoreBreakdown(
            overall_score=85,
            risk_tier="CRITICAL",
            predicted_category="phishing",
            primary_risk_driver="Malicious Link Infrastructure",
            nlp_linguistic_factor=dummy_factor,
            header_transport_factor=dummy_factor,
            authentication_factor=dummy_factor,
            domain_intel_factor=dummy_factor,
            ip_reputation_factor=dummy_factor
        ),
        attribution=OriginAttributionResult(
            archetype="CREDENTIAL_HARVESTING",
            title="Credential Phishing Infrastructure",
            confidence=0.85,
            explanation="Probable origin infrastructure in bulletproof hosting network",
            evidence=["Shortener redirect to IP literal", "Mismatched reply-to"]
        ),
        envelope=EmailEnvelope(
            from_address="security@evil-bank.com",
            from_domain="evil-bank.com",
            reply_to="diverted@scam-mail.org",
            subject="Urgent: Account Verification"
        ),
        authentication=AuthenticationForensics(
            spf=AuthStatus(verdict="fail"),
            dkim=AuthStatus(verdict="none"),
            dmarc=AuthStatus(verdict="fail")
        ),
        relay_path=[
            RelayHop(
                hop_number=1,
                from_ip="198.51.100.5",
                from_host="mta1.badrelay.org",
                by_host="inbound.target.com",
                hop_role="PROBABLE_ORIGIN_INFRASTRUCTURE",
                country="United States",
                asn="AS64496",
                raw="Received: from mta1.badrelay.org"
            ),
            RelayHop(
                hop_number=2,
                from_ip="198.51.100.2",
                from_host="inbound.target.com",
                by_host="mailstore.target.com",
                hop_role="INBOUND_GATEWAY",
                country="United States",
                asn="AS64496",
                raw="Received: from inbound.target.com"
            )
        ],
        infrastructure_evidence=InfrastructureEvidence(
            links=[
                LinkInfrastructure(
                    url="https://bit.ly/verify-account",
                    domain="bit.ly",
                    final_url="http://198.51.100.99/login.php",
                    is_shortener=True,
                    is_raw_ip=False,
                    resolved_ip="198.51.100.99",
                    asn="AS64496 TestNet"
                )
            ],
            mx_infra=MxInfrastructure(
                domain="evil-bank.com",
                primary_mx="mail.evil-bank.com",
                resolved_ip="198.51.100.5",
                isp="Custom MTA"
            )
        ),
        findings=[],
        security_recommendations=["Review suspicious URL redirects."]
    )

    graph = build_single_forensic_graph(res)

    node_ids = {n.id for n in graph.nodes}
    assert "url:https://bit.ly/verify-account" in node_ids
    assert "url:http://198.51.100.99/login.php" in node_ids
    assert "ip:198.51.100.99" in node_ids
    assert "mx:evil-bank.com" in node_ids
    assert "attribution:CREDENTIAL_HARVESTING" in node_ids

    edge_rels = {e.relationship for e in graph.edges}
    assert "CONTAINS_URL" in edge_rels
    assert "EXPANDS_TO" in edge_rels
    assert "HOSTED_BY" in edge_rels
    assert "EXCHANGES_FOR" in edge_rels
    assert "ATTRIBUTED_TO" in edge_rels
    assert "DIVERTS_TO" in edge_rels

def test_case_graph_generation(load_fixture):
    """Verify that build_case_graph correlates case emails, shared links, and hops."""
    db = SessionLocal()
    try:
        # Create a test case
        case = Case(
            id="CASE-TEST-001",
            title="Test Multi-Hop Case Investigation",
            description="Testing graph relationship generation across emails",
            severity="HIGH",
            status="OPEN",
            assigned_to="Forensic Analyst"
        )
        db.add(case)
        db.commit()
        db.refresh(case)

        # Ingest an email
        eml_bytes = load_fixture("forged_received_chain.eml")
        res = analyze_email_headers(eml_bytes)
        
        ce = CaseEmail(
            case_id=case.id,
            message_id=res.envelope.message_id or "msg-1234",
            subject=res.envelope.subject,
            sender=res.envelope.from_address,
            recipient=res.envelope.to_address,
            threat_category="phishing",
            fraud_score=res.fraud_score.overall_score if res.fraud_score else 80,
            risk_tier="CRITICAL",
            origin_ip="203.0.113.88",
            origin_country="US",
            attribution_type="FORGED_HEADERS",
            raw_json=res.model_dump_json() if hasattr(res, "model_dump_json") else json.dumps(res.dict())
        )
        db.add(ce)
        db.commit()

        # Build case graph
        case_graph = build_case_graph(db, case.id)
        assert isinstance(case_graph, ThreatGraphResponse)
        assert case_graph.stats["total_nodes"] > 0
        assert case_graph.stats["total_edges"] > 0

        node_types = {n.type for n in case_graph.nodes}
        assert "case" in node_types
        assert "email" in node_types
        assert "sender" in node_types
        assert "hop" in node_types

        # Clean up
        db.delete(ce)
        db.delete(case)
        db.commit()
    finally:
        db.close()

def test_api_graph_preview_endpoint(client, auth_headers, load_fixture):
    """Test POST /api/forensics/graph-preview returns valid ThreatGraphResponse."""
    eml_bytes = load_fixture("legitimate_email.eml")
    resp = client.post(
        "/api/forensics/graph-preview",
        headers={**auth_headers, "Content-Type": "message/rfc822"},
        content=eml_bytes
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "nodes" in data
    assert "edges" in data
    assert "stats" in data
    assert len(data["nodes"]) >= 3
    assert data["stats"]["total_nodes"] == len(data["nodes"])

def test_api_case_graph_endpoint(client, auth_headers):
    """Test GET /api/cases/{case_id}/graph endpoint."""
    db = SessionLocal()
    case_id = None
    try:
        case = Case(
            id="CASE-TEST-002",
            title="API Graph Test Case",
            description="Testing /api/cases/{id}/graph endpoint",
            severity="MEDIUM",
            status="OPEN"
        )
        db.add(case)
        db.commit()
        db.refresh(case)
        case_id = case.id

        resp = client.get(f"/api/cases/{case_id}/graph", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "nodes" in data
        assert "edges" in data
        assert "stats" in data
        assert data["stats"]["total_nodes"] >= 1
    finally:
        if case_id:
            c = db.query(Case).filter(Case.id == case_id).first()
            if c:
                db.delete(c)
                db.commit()
        db.close()
