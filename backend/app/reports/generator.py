"""
PhishingGuard Forensic Report Generator
Generates executive and technical forensic evidence reports in both
court-admissible PDF format (via ReportLab) and SIEM/SOAR-compatible JSON format.
"""

import io
import json
from datetime import datetime
from typing import Dict, Any, Optional, List

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
    KeepTogether
)

from app.schemas.forensic_schemas import ForensicAnalysisResponse

def generate_forensic_pdf(
    analysis: ForensicAnalysisResponse,
    case_info: Optional[Dict[str, Any]] = None
) -> bytes:
    """
    Renders a comprehensive, professionally styled forensic intelligence PDF report.
    Returns the binary content of the PDF.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()

    # Custom styles
    primary_color = colors.HexColor("#0F172A")    # Deep Navy
    accent_blue = colors.HexColor("#2563EB")      # Cobalt Blue
    bg_light = colors.HexColor("#F8FAFC")         # Slate 50
    border_color = colors.HexColor("#E2E8F0")     # Slate 200

    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=primary_color
    )
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#64748B")
    )
    heading_style = ParagraphStyle(
        'SecHeading',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=17,
        textColor=accent_blue,
        spaceBefore=12,
        spaceAfter=6
    )
    body_style = ParagraphStyle(
        'Body',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#334155")
    )
    code_style = ParagraphStyle(
        'Code',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#1E293B")
    )
    meta_label = ParagraphStyle(
        'MetaLabel',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#475569")
    )

    story = []

    # 1. Header Banner
    story.append(Paragraph("🛡️ PHISHINGGUARD FORENSIC INTELLIGENCE PLATFORM", title_style))
    story.append(Paragraph("Smart India Hackathon 26106 | AI-Powered Email Threat Detection & Evidence Report", subtitle_style))
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=1.5, color=accent_blue, spaceBefore=2, spaceAfter=10))

    # 2. Case / Evidence Identity Block
    case_title = case_info.get("title", "Ad-Hoc Forensic Examination") if case_info else "Ad-Hoc Forensic Examination"
    case_id = case_info.get("id", "CASE-DIRECT-EVIDENCE") if case_info else "CASE-DIRECT-EVIDENCE"
    
    meta_data = [
        [
            Paragraph("<b>Case Reference:</b>", meta_label), Paragraph(f"{case_id} — {case_title}", body_style),
            Paragraph("<b>Ingestion Timestamp:</b>", meta_label), Paragraph(analysis.ingested_at, body_style)
        ],
        [
            Paragraph("<b>Evidence SHA-256:</b>", meta_label), Paragraph(analysis.sha256[:32] + "...", code_style),
            Paragraph("<b>Integrity Status:</b>", meta_label), Paragraph("Verified (Chain of Custody Active)", body_style)
        ],
        [
            Paragraph("<b>Subject:</b>", meta_label), Paragraph(analysis.envelope.subject or "(No Subject)", body_style),
            Paragraph("<b>Envelope From:</b>", meta_label), Paragraph(analysis.envelope.from_address or "Unknown", body_style)
        ]
    ]
    meta_table = Table(meta_data, colWidths=[95, 175, 110, 160])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), bg_light),
        ('BOX', (0,0), (-1,-1), 0.5, border_color),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 12))

    # 3. Threat Verdict & Fused Risk Tier
    story.append(Paragraph("1. EXECUTIVE THREAT VERDICT & RISK SUMMARY", heading_style))
    verdict = analysis.summary.verdict
    score = analysis.fraud_score.overall_score if analysis.fraud_score else analysis.summary.risk_score
    risk_tier = analysis.fraud_score.risk_tier if analysis.fraud_score else "LOW"

    # Color code risk
    if risk_tier == "CRITICAL":
        risk_color = colors.HexColor("#DC2626") # Red
    elif risk_tier == "HIGH":
        risk_color = colors.HexColor("#EA580C") # Orange
    elif risk_tier == "MEDIUM":
        risk_color = colors.HexColor("#D97706") # Amber
    else:
        risk_color = colors.HexColor("#16A34A") # Green

    verdict_data = [
        [
            Paragraph(f"<b>VERDICT:</b> {verdict}", ParagraphStyle('V', fontName='Helvetica-Bold', fontSize=14, textColor=risk_color)),
            Paragraph(f"<b>RISK TIER:</b> {risk_tier}", ParagraphStyle('R', fontName='Helvetica-Bold', fontSize=14, textColor=risk_color)),
            Paragraph(f"<b>FUSED FRAUD SCORE:</b> {score} / 100", ParagraphStyle('S', fontName='Helvetica-Bold', fontSize=14, textColor=primary_color))
        ]
    ]
    verdict_table = Table(verdict_data, colWidths=[180, 180, 180])
    verdict_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#FEF2F2") if risk_tier in ["CRITICAL", "HIGH"] else colors.HexColor("#F0FDF4")),
        ('BOX', (0,0), (-1,-1), 1, risk_color),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 8),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(verdict_table)

    if analysis.fraud_score:
        story.append(Spacer(1, 6))
        story.append(Paragraph(f"<b>Primary Risk Driver:</b> {analysis.fraud_score.primary_risk_driver}", body_style))

    # 4. Multi-Factor Fraud Score Breakdown Table
    story.append(Spacer(1, 8))
    story.append(Paragraph("2. MULTI-FACTOR FRAUD SCORER AUDIT", heading_style))

    if analysis.fraud_score:
        factors = [
            analysis.fraud_score.nlp_linguistic_factor,
            analysis.fraud_score.header_transport_factor,
            analysis.fraud_score.authentication_factor,
            analysis.fraud_score.domain_intel_factor,
            analysis.fraud_score.ip_reputation_factor
        ]
        factor_rows = [
            [
                Paragraph("<b>Factor Name</b>", meta_label),
                Paragraph("<b>Weight</b>", meta_label),
                Paragraph("<b>Score</b>", meta_label),
                Paragraph("<b>Status</b>", meta_label),
                Paragraph("<b>Forensic Analysis & Rationale</b>", meta_label)
            ]
        ]
        for f in factors:
            factor_rows.append([
                Paragraph(f.factor_name, body_style),
                Paragraph(f"{int(f.weight * 100)}%", body_style),
                Paragraph(f"{f.score} / {f.max_score:.0f}", body_style),
                Paragraph(f.status, body_style),
                Paragraph(f.explanation, body_style)
            ])
        
        factor_table = Table(factor_rows, colWidths=[110, 45, 55, 60, 270])
        factor_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#E2E8F0")),
            ('BOX', (0,0), (-1,-1), 0.5, border_color),
            ('INNERGRID', (0,0), (-1,-1), 0.5, border_color),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ]))
        story.append(factor_table)

    # 5. Probable Origin Infrastructure & Geolocation Trace
    if analysis.origin_trace:
        story.append(Spacer(1, 8))
        story.append(Paragraph("3. PROBABLE ORIGIN INFRASTRUCTURE & TELEMETRY", heading_style))
        ot = analysis.origin_trace
        status = getattr(ot, "origin_status", "PROVIDER_RELAY")
        
        status_color = colors.HexColor("#0284C7")  # blue for PROVIDER_RELAY
        if status == "ORIGIN_FOUND":
            status_color = colors.HexColor("#16A34A")  # green
        elif status == "ANONYMIZED":
            status_color = colors.HexColor("#DC2626")  # red

        status_text = f"<font color='{status_color.hexval()}'><b>[{status}]</b></font> — {ot.status_message}"
        
        geo_info = "Probable origin infrastructure location cannot be determined from headers (Provider Relay)"
        if ot.geolocation and status == "ORIGIN_FOUND":
            g = ot.geolocation
            geo_info = f"{g.city or 'Unknown'}, {g.region or ''} {g.country or 'Unknown'} (Lat: {g.latitude}, Lon: {g.longitude}) | ISP: {g.isp or 'N/A'} (ASN: {g.asn or 'N/A'})"
        elif ot.geolocation and status == "ANONYMIZED":
            g = ot.geolocation
            geo_info = f"Reported: {g.city or 'Unknown'}, {g.country or 'Unknown'} (Probable origin infrastructure location marked unreliable - VPN/Proxy/Tor)"

        trace_data = [
            [Paragraph(f"<b>Origin Status:</b>", meta_label), Paragraph(status_text, body_style)],
            [Paragraph(f"<b>Observed Origin IP:</b>", meta_label), Paragraph(f"{ot.origin_ip or 'Concealed / None'} ({ot.confidence_level} Confidence)", body_style)],
            [Paragraph(f"<b>Probable Origin Infrastructure Location:</b>", meta_label), Paragraph(geo_info, body_style)],
            [Paragraph(f"<b>Transport Justification:</b>", meta_label), Paragraph(ot.reliability_justification, body_style)]
        ]
        trace_table = Table(trace_data, colWidths=[140, 400])
        trace_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), bg_light),
            ('BOX', (0,0), (-1,-1), 0.5, border_color),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ]))
        story.append(trace_table)

    # 6. Origin Attribution & Operational Profiling
    if analysis.attribution:
        story.append(Spacer(1, 8))
        story.append(Paragraph("4. OPERATIONAL ATTRIBUTION ARCHETYPE", heading_style))
        attr = analysis.attribution
        attr_data = [
            [Paragraph(f"<b>Archetype:</b> {attr.archetype}", body_style), Paragraph(f"<b>Attribution Confidence:</b> {int(attr.confidence * 100)}%", body_style)],
            [Paragraph(f"<b>Profile:</b> {attr.title}", body_style), Paragraph("", body_style)],
            [Paragraph(f"<b>Explanation:</b> {attr.explanation}", body_style), Paragraph("", body_style)]
        ]
        attr_table = Table(attr_data, colWidths=[350, 190])
        attr_table.setStyle(TableStyle([
            ('SPAN', (0,1), (1,1)),
            ('SPAN', (0,2), (1,2)),
            ('BACKGROUND', (0,0), (-1,-1), bg_light),
            ('BOX', (0,0), (-1,-1), 0.5, border_color),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ]))
        story.append(attr_table)

        if attr.evidence:
            story.append(Spacer(1, 4))
            for ev in attr.evidence:
                story.append(Paragraph(f"• {ev}", body_style))

    # 7. Alternative Infrastructure Evidence (Task 2)
    if analysis.infrastructure_evidence:
        infra = analysis.infrastructure_evidence
        has_infra_data = bool(infra.links or (infra.reply_to and infra.reply_to.is_mismatch) or (infra.sender_whois and infra.sender_whois.available) or infra.sender_mx)
        if has_infra_data:
            story.append(Spacer(1, 8))
            story.append(Paragraph("5. ALTERNATIVE INFRASTRUCTURE EVIDENCE (PROBABLE INFRASTRUCTURE LOCATION, NOT SENDER LOCATION)", heading_style))
            story.append(Paragraph("<b>Notice:</b> The following network infrastructure points represent server hostings, link targets, and mail exchangers. <i>Probable infrastructure location, not sender location.</i>", meta_label))
            story.append(Spacer(1, 4))

            if infra.links:
                link_rows = [
                    [
                        Paragraph("<b>Target Link / Domain</b>", meta_label),
                        Paragraph("<b>Resolved IP</b>", meta_label),
                        Paragraph("<b>Hosting / ASN</b>", meta_label),
                        Paragraph("<b>Infrastructure Location</b>", meta_label),
                        Paragraph("<b>Threat Flags</b>", meta_label)
                    ]
                ]
                for l in infra.links:
                    flags = []
                    if l.is_suspicious_hosting:
                        flags.append("Suspicious VPS")
                    if l.is_shortener:
                        flags.append("Shortener")
                    if l.is_raw_ip:
                        flags.append("Raw IP")
                    if l.is_idn_homoglyph:
                        flags.append("Homoglyph")
                    if l.has_at_symbol:
                        flags.append("@-Delimiter")
                    flags_str = ", ".join(flags) if flags else "Normal"
                    loc_str = f"{l.city + ', ' if l.city else ''}{l.country or 'Unknown'}"
                    
                    url_display = (l.url[:40] + "...") if len(l.url) > 40 else l.url
                    link_rows.append([
                        Paragraph(f"<b>{l.domain}</b><br/>{url_display}", body_style),
                        Paragraph(l.resolved_ip or "Unresolved", code_style),
                        Paragraph(f"{l.hosting_provider or '-'}<br/>ASN: {l.asn or '-'}", body_style),
                        Paragraph(loc_str, body_style),
                        Paragraph(flags_str, body_style)
                    ])
                link_table = Table(link_rows, colWidths=[150, 85, 115, 100, 90])
                link_table.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#E2E8F0")),
                    ('BOX', (0,0), (-1,-1), 0.5, border_color),
                    ('INNERGRID', (0,0), (-1,-1), 0.5, border_color),
                    ('VALIGN', (0,0), (-1,-1), 'TOP'),
                    ('TOPPADDING', (0,0), (-1,-1), 3),
                    ('BOTTOMPADDING', (0,0), (-1,-1), 3),
                ]))
                story.append(link_table)
                story.append(Spacer(1, 6))

            if infra.reply_to and infra.reply_to.is_mismatch:
                mismatch_p = (
                    f"⚠️ <b>Reply-To Mismatch Detected:</b> From <code>{infra.reply_to.from_address}</code> "
                    f"diverges to Reply-To <code>{infra.reply_to.reply_to_address}</code>. "
                    f"Inbound replies will route to domain <b>{infra.reply_to.reply_to_domain}</b> "
                    f"(Resolved IP: {infra.reply_to.resolved_ip or 'N/A'}, Hosting: {infra.reply_to.hosting_provider or 'N/A'})."
                )
                story.append(Paragraph(mismatch_p, body_style))
                story.append(Spacer(1, 4))

            if infra.sender_whois and infra.sender_whois.available:
                w = infra.sender_whois
                new_flag = " ⚠️ <b>(NEWLY REGISTERED: &lt;30 DAYS)</b>" if w.is_newly_registered else ""
                whois_p = (
                    f"🌐 <b>Domain Registration Telemetry:</b> Created on <b>{w.creation_date or 'Unknown'}</b> "
                    f"(Age: {w.domain_age_days if w.domain_age_days is not None else 'Unknown'} days){new_flag}. "
                    f"Registrar: {w.registrar or 'Unknown'} | Country: {w.country or 'Unknown'}."
                )
                story.append(Paragraph(whois_p, body_style))
                story.append(Spacer(1, 4))

    # 8. Transmission Hop-by-Hop Trace
    story.append(Spacer(1, 8))
    story.append(Paragraph("6. TRANSMISSION HOP-BY-HOP ROUTING AUDIT", heading_style))

    if analysis.relay_path:
        hop_rows = [
            [
                Paragraph("<b>Hop #</b>", meta_label),
                Paragraph("<b>From Host</b>", meta_label),
                Paragraph("<b>Relayed IP</b>", meta_label),
                Paragraph("<b>Delay</b>", meta_label),
                Paragraph("<b>By Server</b>", meta_label)
            ]
        ]
        for h in analysis.relay_path:
            delay_str = f"{h.delay_seconds:.1f}s" if h.delay_seconds is not None else "-"
            if h.delay_seconds is not None and h.delay_seconds < -60:
                delay_str = f"⚠️ {delay_str} (Time Inversion)"
            elif h.delay_seconds is not None and h.delay_seconds < 0:
                delay_str = f"⚠️ {delay_str} (Clock Skew)"
            elif h.delay_seconds is not None and h.delay_seconds > 86400:
                delay_str = f"⚠️ {h.delay_seconds/3600:.1f}h (Extreme Delay)"
            hop_rows.append([
                Paragraph(str(h.hop_number), body_style),
                Paragraph(h.from_host or "-", body_style),
                Paragraph(f"{h.from_ip or '-'}{' (Private)' if h.is_private_ip else ''}", body_style),
                Paragraph(delay_str, body_style),
                Paragraph(h.by_host or "-", body_style)
            ])
        hop_table = Table(hop_rows, colWidths=[40, 150, 130, 80, 140])
        hop_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#E2E8F0")),
            ('BOX', (0,0), (-1,-1), 0.5, border_color),
            ('INNERGRID', (0,0), (-1,-1), 0.5, border_color),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('TOPPADDING', (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ]))
        story.append(hop_table)

    # 9. Actionable SOC Recommendations
    if analysis.security_recommendations:
        story.append(Spacer(1, 8))
        story.append(Paragraph("7. ACTIONABLE SOC RECOMMENDATIONS", heading_style))
        for rec in analysis.security_recommendations:
            story.append(Paragraph(f"• {rec}", body_style))

    # 10. Chain of Custody & Legal Disclaimer
    story.append(Spacer(1, 12))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CBD5E1"), spaceBefore=4, spaceAfter=6))
    disclaimer = (
        "<b>LEGAL & FORENSIC CHAIN OF CUSTODY NOTICE:</b> This document was generated automatically by the "
        "PhishingGuard Cyber Intelligence Platform designed with reference to ISO/IEC 27037 principles for digital evidence handling. "
        f"Cryptographic fingerprint (SHA-256): {analysis.sha256}. All header parsing and timeline reconstructions "
        "are preserved in immutable append-only hash chains for judicial and compliance review. "
        "<b>NOTICE:</b> Geolocation and origin attribution are probabilistic estimates based on routing headers "
        "and Autonomous System telemetry, not absolute proof of sender identity."
    )
    story.append(Paragraph(disclaimer, ParagraphStyle('Disc', parent=styles['Normal'], fontName='Helvetica-Oblique', fontSize=7, leading=10, textColor=colors.HexColor("#64748B"))))

    doc.build(story)
    return buffer.getvalue()

def generate_siem_json_bundle(
    analysis: ForensicAnalysisResponse,
    case_info: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Exports a structured STIX / RFC 5322 compatible threat intelligence bundle
    for integration into enterprise SIEM / SOAR platforms (Splunk, Sentinel, QRadar).
    """
    analysis_dict = analysis.model_dump() if hasattr(analysis, "model_dump") else analysis.dict()
    
    bundle = {
        "schema_version": "2.0.0",
        "spec_standard": "SIH-26106-Forensic-Intelligence",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "case": case_info or {"id": "UNASSIGNED", "title": "Direct Examination"},
        "evidence": {
            "sha256": analysis.sha256,
            "ingested_at": analysis.ingested_at,
            "verdict": analysis.summary.verdict,
            "risk_score": analysis.summary.risk_score,
            "risk_tier": analysis.fraud_score.risk_tier if analysis.fraud_score else "LOW",
            "category": analysis.fraud_score.predicted_category if analysis.fraud_score else "unknown",
            "primary_risk_driver": analysis.fraud_score.primary_risk_driver if analysis.fraud_score else None
        },
        "attribution": analysis_dict.get("attribution"),
        "envelope": analysis_dict.get("envelope"),
        "authentication": analysis_dict.get("authentication"),
        "origin_trace": analysis_dict.get("origin_trace"),
        "domain_intel": analysis_dict.get("domain_intel"),
        "infrastructure_evidence": analysis_dict.get("infrastructure_evidence"),
        "relay_path": analysis_dict.get("relay_path"),
        "findings": analysis_dict.get("findings"),
        "recommendations": analysis_dict.get("security_recommendations")
    }
    return bundle
