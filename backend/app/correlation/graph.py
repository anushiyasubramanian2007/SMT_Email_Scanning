"""
PhishingGuard Threat Graph Engine
Builds multi-dimensional threat relationship graphs using NetworkX
and serializes them into D3.js / Cytoscape JSON format for SOC analysts.
"""

from typing import Dict, List, Optional, Any, Set
import networkx as nx
from sqlalchemy.orm import Session
import json

from app.schemas.forensic_schemas import (
    GraphNode,
    GraphEdge,
    ThreatGraphResponse,
    ForensicAnalysisResponse
)
from app.database.db import (
    Case,
    CaseEmail,
    ThreatIndicator,
    ThreatCampaign,
    EmailIndicatorAssociation
)

def build_case_graph(db: Session, case_id: str) -> ThreatGraphResponse:
    """
    Constructs a NetworkX graph linking all emails, senders, domains,
    origin IPs, ASNs, Geolocation countries, and URLs within an investigation case.
    """
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        return ThreatGraphResponse(
            nodes=[],
            edges=[],
            stats={"error": f"Case {case_id} not found", "total_nodes": 0, "total_edges": 0}
        )

    G = nx.Graph()

    # 1. Add Central Case Node
    case_node_id = f"case:{case.id}"
    G.add_node(
        case_node_id,
        label=f"Case: {case.title}",
        type="case",
        risk=case.severity or "MEDIUM",
        score=75 if case.severity == "CRITICAL" else 50,
        details={
            "id": case.id,
            "status": case.status,
            "severity": case.severity,
            "assigned_to": case.assigned_to,
            "created_at": str(case.created_at)
        }
    )

    emails = db.query(CaseEmail).filter(CaseEmail.case_id == case.id).all()
    campaigns_seen: Set[str] = set()

    for ce in emails:
        email_node_id = f"email:{ce.id}"
        risk_tier = ce.risk_tier or "LOW"
        G.add_node(
            email_node_id,
            label=ce.subject or f"Email #{ce.id}",
            type="email",
            risk=risk_tier,
            score=ce.fraud_score or 0,
            details={
                "id": ce.id,
                "message_id": ce.message_id,
                "subject": ce.subject,
                "sender": ce.sender,
                "category": ce.threat_category,
                "attribution": ce.attribution_type
            }
        )
        # Link Case -> Email
        G.add_edge(case_node_id, email_node_id, relationship="INCLUDES", weight=1.0)

        # 2. Add Sender Node
        if ce.sender:
            sender_node_id = f"sender:{ce.sender.lower()}"
            if not G.has_node(sender_node_id):
                G.add_node(
                    sender_node_id,
                    label=ce.sender,
                    type="sender",
                    risk="CRITICAL" if risk_tier in ["CRITICAL", "HIGH"] else "MEDIUM",
                    score=ce.fraud_score or 50,
                    details={"address": ce.sender}
                )
            G.add_edge(email_node_id, sender_node_id, relationship="SENT_BY", weight=1.2)

            # Sender Domain
            if "@" in ce.sender:
                s_domain = ce.sender.split("@")[-1].lower()
                dom_node_id = f"domain:{s_domain}"
                if not G.has_node(dom_node_id):
                    G.add_node(
                        dom_node_id,
                        label=s_domain,
                        type="domain",
                        risk="HIGH" if risk_tier in ["CRITICAL", "HIGH"] else "LOW",
                        score=ce.fraud_score or 30,
                        details={"domain": s_domain}
                    )
                G.add_edge(sender_node_id, dom_node_id, relationship="HOSTED_ON", weight=1.0)

        # 3. Add Origin IP & Geolocation
        if ce.origin_ip:
            ip_node_id = f"ip:{ce.origin_ip}"
            if not G.has_node(ip_node_id):
                G.add_node(
                    ip_node_id,
                    label=ce.origin_ip,
                    type="ip",
                    risk="CRITICAL" if risk_tier == "CRITICAL" else "MEDIUM",
                    score=ce.fraud_score or 40,
                    details={"ip": ce.origin_ip, "country": ce.origin_country}
                )
            G.add_edge(email_node_id, ip_node_id, relationship="ORIGIN_IP", weight=1.2)

            # Add Country / Geo node
            if ce.origin_country:
                geo_node_id = f"geo:{ce.origin_country.lower()}"
                if not G.has_node(geo_node_id):
                    G.add_node(
                        geo_node_id,
                        label=f"Country: {ce.origin_country}",
                        type="geo",
                        risk="LOW",
                        score=10,
                        details={"country": ce.origin_country}
                    )
                G.add_edge(ip_node_id, geo_node_id, relationship="LOCATED_IN", weight=0.8)

        # 4. Campaign Association
        if ce.campaign_id and ce.campaign_id not in campaigns_seen:
            campaigns_seen.add(ce.campaign_id)
            camp = db.query(ThreatCampaign).filter(ThreatCampaign.id == ce.campaign_id).first()
            if camp:
                camp_node_id = f"campaign:{camp.id}"
                if not G.has_node(camp_node_id):
                    G.add_node(
                        camp_node_id,
                        label=camp.name,
                        type="campaign",
                        risk="CRITICAL",
                        score=90,
                        details={
                            "id": camp.id,
                            "actor_type": camp.threat_actor_type,
                            "status": camp.status,
                            "primary_ioc": camp.primary_ioc
                        }
                    )
                G.add_edge(email_node_id, camp_node_id, relationship="CORRELATED_WITH", weight=1.5)

        # 5. Extract URLs, Hops, and Infrastructure Evidence from raw_json if stored
        if ce.raw_json:
            try:
                raw_data = json.loads(ce.raw_json)
                
                # Multi-hop relays in case context
                raw_hops = raw_data.get("relay_path", [])
                prev_hop_id = None
                for rh in raw_hops:
                    h_num = rh.get("hop_number")
                    h_ip = rh.get("from_ip")
                    h_flag = rh.get("delay_flag")
                    if h_num is not None:
                        hop_node_id = f"hop:{h_num}:{ce.id}"
                        G.add_node(
                            hop_node_id,
                            label=f"Hop #{h_num} ({h_ip or rh.get('from_host') or 'Relay'})",
                            type="hop",
                            risk="CRITICAL" if h_flag == "TIME_INVERSION" else "MEDIUM",
                            score=80 if h_flag == "TIME_INVERSION" else 20,
                            details=rh
                        )
                        if prev_hop_id:
                            rel = "INVERTED_RELAY_TO" if h_flag == "TIME_INVERSION" else "RELAYED_TO"
                            G.add_edge(prev_hop_id, hop_node_id, relationship=rel, weight=1.0)
                        prev_hop_id = hop_node_id
                        if h_num == len(raw_hops):
                            G.add_edge(hop_node_id, email_node_id, relationship="INGRESS_TO", weight=1.1)

                # Link infrastructure
                infra = raw_data.get("infrastructure_evidence", {}) or {}
                links = infra.get("link_infrastructure", [])
                for link in links:
                    u = link.get("url")
                    if u:
                        url_node_id = f"url:{u}"
                        if not G.has_node(url_node_id):
                            G.add_node(
                                url_node_id,
                                label=u[:40] + ("..." if len(u) > 40 else ""),
                                type="url",
                                risk="CRITICAL" if link.get("is_shortener") or link.get("is_ip_literal") else "HIGH",
                                score=85,
                                details=link
                            )
                        G.add_edge(email_node_id, url_node_id, relationship="CONTAINS_URL", weight=1.2)

                        dest = link.get("final_destination")
                        if dest and dest != u:
                            dest_node_id = f"url:{dest}"
                            if not G.has_node(dest_node_id):
                                G.add_node(
                                    dest_node_id,
                                    label=dest[:40] + ("..." if len(dest) > 40 else ""),
                                    type="url",
                                    risk="HIGH",
                                    score=80,
                                    details={"url": dest, "redirected_from": u}
                                )
                            G.add_edge(url_node_id, dest_node_id, relationship="EXPANDS_TO", weight=1.4)

                        for hip in link.get("hosting_ips", [])[:2]:
                            hip_node_id = f"ip:{hip}"
                            if not G.has_node(hip_node_id):
                                G.add_node(
                                    hip_node_id,
                                    label=f"Host: {hip}",
                                    type="ip",
                                    risk="HIGH",
                                    score=70,
                                    details={"ip": hip, "hosting_target": link.get("domain")}
                                )
                            G.add_edge(url_node_id, hip_node_id, relationship="HOSTED_BY", weight=1.0)

                # Check for URLs in security findings fallback
                for f in raw_data.get("findings", []):
                    f_id = f.get("id", "")
                    if "URL" in f_id or "PHISH" in f_id:
                        details_text = f.get("details", "")
                        for word in details_text.split():
                            if word.startswith("http://") or word.startswith("https://"):
                                url_clean = word.rstrip(".,;:)'\"")
                                url_node_id = f"url:{url_clean}"
                                if not G.has_node(url_node_id):
                                    G.add_node(
                                        url_node_id,
                                        label=url_clean[:40] + ("..." if len(url_clean) > 40 else ""),
                                        type="url",
                                        risk="CRITICAL",
                                        score=95,
                                        details={"url": url_clean}
                                    )
                                G.add_edge(email_node_id, url_node_id, relationship="CONTAINS_URL", weight=1.2)
            except Exception:
                pass

    return _nx_to_threat_graph(G)

def build_single_forensic_graph(res: ForensicAnalysisResponse) -> ThreatGraphResponse:
    """
    Constructs a graph from a single live ForensicAnalysisResponse without requiring DB persistence.
    Ideal for instant visualization in the analyst preview and SIEM relationship mapping.
    """
    G = nx.Graph()

    # Root Email Node
    email_node_id = f"email:{res.sha256[:12]}"
    risk_tier = res.fraud_score.risk_tier if res.fraud_score else ("CRITICAL" if res.summary.risk_score >= 70 else "MEDIUM")
    score = res.fraud_score.overall_score if res.fraud_score else res.summary.risk_score

    G.add_node(
        email_node_id,
        label=res.envelope.subject or "Analyzed Email",
        type="email",
        risk=risk_tier,
        score=score,
        details={
            "sha256": res.sha256,
            "verdict": res.summary.verdict,
            "category": res.fraud_score.predicted_category if res.fraud_score else "unknown",
            "attribution": res.attribution.archetype if res.attribution else "none"
        }
    )

    # Sender Node & Domain
    dom_node_id = None
    if res.envelope.from_address:
        sender_node_id = f"sender:{res.envelope.from_address.lower()}"
        G.add_node(
            sender_node_id,
            label=f"{res.envelope.from_display_name} <{res.envelope.from_address}>" if res.envelope.from_display_name else res.envelope.from_address,
            type="sender",
            risk="CRITICAL" if risk_tier in ["CRITICAL", "HIGH"] else "LOW",
            score=score,
            details={"address": res.envelope.from_address}
        )
        G.add_edge(email_node_id, sender_node_id, relationship="SENT_BY", weight=1.2)

        # Domain Node
        if res.envelope.from_domain:
            dom_node_id = f"domain:{res.envelope.from_domain.lower()}"
            is_lookalike = res.domain_intel.is_lookalike if res.domain_intel else False
            G.add_node(
                dom_node_id,
                label=res.envelope.from_domain,
                type="domain",
                risk="CRITICAL" if is_lookalike else ("LOW" if risk_tier == "LOW" else "MEDIUM"),
                score=95 if is_lookalike else 20,
                details={
                    "domain": res.envelope.from_domain,
                    "lookalike": is_lookalike,
                    "age_days": res.domain_intel.domain_age_days if res.domain_intel else None
                }
            )
            G.add_edge(sender_node_id, dom_node_id, relationship="HOSTED_ON", weight=1.0)

    # Reply-To Node if present and diverted
    if res.envelope.reply_to and res.envelope.reply_to.lower() != (res.envelope.from_address or "").lower():
        reply_node_id = f"sender:{res.envelope.reply_to.lower()}"
        G.add_node(
            reply_node_id,
            label=f"Reply-To: {res.envelope.reply_to}",
            type="sender",
            risk="CRITICAL",
            score=90,
            details={"address": res.envelope.reply_to, "diversion": True}
        )
        G.add_edge(email_node_id, reply_node_id, relationship="DIVERTS_TO", weight=1.5)

    # Origin IP Node & Geo / ASN
    origin_ip_node_id = None
    if res.origin_trace and res.origin_trace.origin_ip:
        ip = res.origin_trace.origin_ip
        origin_ip_node_id = f"ip:{ip}"
        geo = res.origin_trace.geolocation
        is_tor = geo.is_tor if geo else False
        is_vpn = geo.is_vpn_proxy if geo else False
        ip_risk = "CRITICAL" if (is_tor or is_vpn) else ("HIGH" if risk_tier == "CRITICAL" else "LOW")

        G.add_node(
            origin_ip_node_id,
            label=ip,
            type="ip",
            risk=ip_risk,
            score=95 if is_tor else (75 if is_vpn else 30),
            details={
                "ip": ip,
                "is_tor": is_tor,
                "is_vpn": is_vpn,
                "isp": geo.isp if geo else None,
                "origin_status": res.origin_trace.origin_status
            }
        )
        G.add_edge(email_node_id, origin_ip_node_id, relationship="ROUTED_VIA", weight=1.2)

        if geo and geo.country:
            geo_node_id = f"geo:{geo.country_code or geo.country}"
            if not G.has_node(geo_node_id):
                G.add_node(
                    geo_node_id,
                    label=f"{geo.city + ', ' if geo.city else ''}{geo.country}",
                    type="geo",
                    risk="LOW",
                    score=10,
                    details={"country": geo.country, "city": geo.city}
                )
            G.add_edge(origin_ip_node_id, geo_node_id, relationship="LOCATED_IN", weight=0.8)

        if geo and geo.asn:
            asn_node_id = f"asn:{geo.asn.split()[0]}"
            if not G.has_node(asn_node_id):
                G.add_node(
                    asn_node_id,
                    label=f"{geo.asn} ({geo.org or geo.isp or 'Autonomous System'})",
                    type="asn",
                    risk="MEDIUM" if (is_tor or is_vpn) else "LOW",
                    score=25,
                    details={"asn": geo.asn, "org": geo.org}
                )
            G.add_edge(origin_ip_node_id, asn_node_id, relationship="OPERATED_BY", weight=0.9)

    # Multi-Hop Relay Sequence
    if res.relay_path and len(res.relay_path) > 0:
        prev_hop_id = None
        for h in res.relay_path:
            h_node_id = f"hop:{h.hop_number}"
            is_inversion = h.delay_flag == "TIME_INVERSION"
            is_extreme = h.delay_flag == "EXTREME_DELAY"
            is_skew = h.delay_flag == "CLOCK_SKEW"
            h_risk = "CRITICAL" if is_inversion else ("HIGH" if is_extreme else ("LOW" if h.is_provider_relay else "MEDIUM"))
            h_score = 95 if is_inversion else (70 if is_extreme else (40 if is_skew else 20))
            
            hop_label = f"Hop #{h.hop_number}: {h.from_ip or h.from_host or 'Relay'}"
            G.add_node(
                h_node_id,
                label=hop_label,
                type="hop",
                risk=h_risk,
                score=h_score,
                details={
                    "hop_number": h.hop_number,
                    "from_ip": h.from_ip,
                    "from_host": h.from_host,
                    "by_host": h.by_host,
                    "protocol": h.protocol,
                    "timestamp": h.timestamp,
                    "role": h.hop_role,
                    "delay_seconds": h.delay_seconds,
                    "delay_flag": h.delay_flag,
                    "country": h.country,
                    "city": h.city,
                    "asn": h.asn,
                    "isp": h.isp,
                    "is_provider_relay": h.is_provider_relay,
                    "provider_name": h.provider_name,
                    "is_private_ip": h.is_private_ip
                }
            )

            if prev_hop_id:
                rel = "INVERTED_RELAY_TO" if is_inversion else "RELAYED_TO"
                w = 2.0 if is_inversion else 1.0
                G.add_edge(prev_hop_id, h_node_id, relationship=rel, weight=w)
            prev_hop_id = h_node_id

        # Link Last Hop (Inbound Gateway) to Email
        last_hop = res.relay_path[-1]
        last_hop_id = f"hop:{last_hop.hop_number}"
        G.add_edge(last_hop_id, email_node_id, relationship="INGRESS_TO", weight=1.3)

        # Link Origin Hop to Origin IP if available
        if origin_ip_node_id:
            matching_hop = next((h for h in res.relay_path if h.from_ip == res.origin_trace.origin_ip), None)
            if matching_hop:
                target_hop_id = f"hop:{matching_hop.hop_number}"
                G.add_edge(target_hop_id, origin_ip_node_id, relationship="EMITS_FROM", weight=1.2)
            else:
                first_hop_id = f"hop:{res.relay_path[0].hop_number}"
                G.add_edge(first_hop_id, origin_ip_node_id, relationship="TRANSMITS_FROM", weight=1.0)

    # Infrastructure Evidence: Links, MX, Reply-To
    if res.infrastructure_evidence:
        # 1. Links & Hosting
        infra_links = getattr(res.infrastructure_evidence, "link_infrastructure", None) or getattr(res.infrastructure_evidence, "links", [])
        if infra_links:
            for link in infra_links:
                url_node_id = f"url:{link.url}"
                final_dest = getattr(link, "final_url", None) or getattr(link, "final_destination", None) or link.url
                resolved_ip = getattr(link, "resolved_ip", None)
                hosting_ips = getattr(link, "hosting_ips", None) or ([resolved_ip] if resolved_ip else [])
                is_suspicious_url = (
                    getattr(link, "is_shortener", False) or
                    getattr(link, "is_raw_ip", False) or
                    getattr(link, "is_ip_literal", False) or
                    getattr(link, "has_idn_homoglyph", False) or
                    getattr(link, "has_at_symbol", False) or
                    getattr(link, "is_suspicious_hosting", False)
                )
                u_risk = "CRITICAL" if is_suspicious_url else ("HIGH" if getattr(link, "virustotal_positives", 0) else "MEDIUM")
                u_score = 90 if is_suspicious_url else 50

                if not G.has_node(url_node_id):
                    G.add_node(
                        url_node_id,
                        label=link.url[:36] + ("..." if len(link.url) > 36 else ""),
                        type="url",
                        risk=u_risk,
                        score=u_score,
                        details={
                            "url": link.url,
                            "domain": link.domain,
                            "final_destination": final_dest,
                            "is_shortener": getattr(link, "is_shortener", False),
                            "asn": getattr(link, "asn", None),
                            "hosting_ips": hosting_ips,
                            "vt_positives": getattr(link, "virustotal_positives", 0)
                        }
                    )
                G.add_edge(email_node_id, url_node_id, relationship="CONTAINS_URL", weight=1.2)

                dest_anchor_id = url_node_id
                if final_dest and final_dest != link.url:
                    dest_node_id = f"url:{final_dest}"
                    if not G.has_node(dest_node_id):
                        G.add_node(
                            dest_node_id,
                            label=final_dest[:36] + ("..." if len(final_dest) > 36 else ""),
                            type="url",
                            risk=u_risk,
                            score=u_score,
                            details={"url": final_dest, "redirected_from": link.url}
                        )
                    G.add_edge(url_node_id, dest_node_id, relationship="EXPANDS_TO", weight=1.4)
                    dest_anchor_id = dest_node_id

                if hosting_ips:
                    for hip in hosting_ips[:3]:
                        hip_node_id = f"ip:{hip}"
                        if not G.has_node(hip_node_id):
                            G.add_node(
                                hip_node_id,
                                label=f"Host: {hip}",
                                type="ip",
                                risk="HIGH" if is_suspicious_url else "MEDIUM",
                                score=70,
                                details={"ip": hip, "hosting_domain": link.domain}
                            )
                        G.add_edge(dest_anchor_id, hip_node_id, relationship="HOSTED_BY", weight=1.0)

                link_asn = getattr(link, "asn", None)
                if link_asn:
                    lasn_id = f"asn:{link_asn.split()[0]}"
                    if not G.has_node(lasn_id):
                        G.add_node(
                            lasn_id,
                            label=f"ASN: {link_asn}",
                            type="asn",
                            risk="MEDIUM",
                            score=35,
                            details={"asn": link_asn}
                        )
                    G.add_edge(dest_anchor_id, lasn_id, relationship="OPERATED_BY", weight=0.9)

        # 2. MX Infrastructure
        mx = getattr(res.infrastructure_evidence, "mx_infrastructure", None) or getattr(res.infrastructure_evidence, "mx_infra", None)
        if mx and getattr(mx, "domain", None):
            if mx.domain:
                mx_node_id = f"mx:{mx.domain.lower()}"
                mx_provider = getattr(mx, "provider_family", None) or getattr(mx, "hosting_provider", None) or mx.domain
                is_null = getattr(mx, "is_null_mx", False)
                is_direct = getattr(mx, "direct_ip_mx", False)
                if not G.has_node(mx_node_id):
                    mx_risk = "CRITICAL" if (is_null or is_direct) else ("LOW" if mx_provider in ["Google Workspace", "Microsoft 365"] else "MEDIUM")
                    G.add_node(
                        mx_node_id,
                        label=f"MX: {mx_provider}",
                        type="mx",
                        risk=mx_risk,
                        score=90 if (is_null or is_direct) else 20,
                        details={
                            "domain": mx.domain,
                            "provider": mx_provider,
                            "primary_mx": getattr(mx, "primary_mx", None),
                            "resolved_ip": getattr(mx, "resolved_ip", None),
                            "is_null_mx": is_null,
                            "direct_ip_mx": is_direct
                        }
                    )
                if dom_node_id and G.has_node(dom_node_id):
                    G.add_edge(dom_node_id, mx_node_id, relationship="EXCHANGES_FOR", weight=1.1)

    # Attribution Node
    if res.attribution:
        attr_node_id = f"attribution:{res.attribution.archetype}"
        evidence_list = getattr(res.attribution, "evidence", getattr(res.attribution, "evidence_chain", []))
        G.add_node(
            attr_node_id,
            label=res.attribution.title,
            type="campaign",
            risk="CRITICAL" if res.attribution.archetype in ["COMPROMISED_ACCOUNT", "ANONYMIZED_INFRASTRUCTURE", "SPOOFED_IDENTITY"] else "LOW",
            score=int(res.attribution.confidence * 100),
            details={
                "archetype": res.attribution.archetype,
                "confidence": res.attribution.confidence,
                "evidence_chain": evidence_list
            }
        )
        G.add_edge(email_node_id, attr_node_id, relationship="ATTRIBUTED_TO", weight=1.3)

    return _nx_to_threat_graph(G)

def _nx_to_threat_graph(G: nx.Graph) -> ThreatGraphResponse:
    """Serializes a NetworkX Graph to Pydantic ThreatGraphResponse."""
    nodes: List[GraphNode] = []
    edges: List[GraphEdge] = []

    for n_id, attrs in G.nodes(data=True):
        nodes.append(
            GraphNode(
                id=n_id,
                label=attrs.get("label", n_id),
                type=attrs.get("type", "unknown"),
                risk=attrs.get("risk", "LOW"),
                score=attrs.get("score", 0),
                details=attrs.get("details", {})
            )
        )

    for u, v, attrs in G.edges(data=True):
        edges.append(
            GraphEdge(
                source=u,
                target=v,
                relationship=attrs.get("relationship", "CONNECTED_TO"),
                weight=attrs.get("weight", 1.0)
            )
        )

    # Compute network metrics
    total_nodes = len(nodes)
    total_edges = len(edges)
    density = nx.density(G) if total_nodes > 1 else 0.0

    # Find highest risk node
    highest_risk = "LOW"
    risk_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "CLEAN": 0}
    for n in nodes:
        if risk_rank.get(n.risk, 0) > risk_rank.get(highest_risk, 0):
            highest_risk = n.risk

    return ThreatGraphResponse(
        nodes=nodes,
        edges=edges,
        stats={
            "total_nodes": total_nodes,
            "total_edges": total_edges,
            "graph_density": round(density, 3),
            "highest_risk": highest_risk
        }
    )
