"""
Generate PhishingGuard Project Documentation in both .DOCX and .PDF formats,
strictly conforming to the reference PDF structure:
- 23CS56C Simulation Using Modern Tools
- National Engineering College, Kovilpatti (Anna University) format
- Complete with Cover Page, Bonafide Certificate, Abstract, Table of Contents,
  Chapters 1 to 7, and Elaborate Mathematical Models.
"""

import os
import sys
from datetime import datetime

# Configure Windows UTF-8 stdout
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

# ==============================================================================
# PART 1: REPORTLAB PDF GENERATION WITH EXACT ACADEMIC PAGE BORDER & FOOTERS
# ==============================================================================
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    KeepTogether,
    HRFlowable
)
from reportlab.pdfgen import canvas

class AcademicNumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas that adds the exact academic rectangular page border
    and page numbering in the format of the reference PDF.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        self.saveState()
        width, height = self._pagesize

        # Draw outer academic border line (identical to National Engineering College format)
        border_margin = 36  # 0.5 inch
        self.setStrokeColor(colors.black)
        self.setLineWidth(1.0)
        self.rect(border_margin, border_margin, width - 2 * border_margin, height - 2 * border_margin)

        # Bottom-right page number
        self.setFont("Times-Roman", 11)
        self.drawRightString(width - border_margin - 20, border_margin + 15, str(self._pageNumber))

        self.restoreState()


def build_pdf(output_path: str):
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54
    )

    styles = getSampleStyleSheet()

    # Academic Typography Styles (Times-Roman / Times-Bold / Times-Italic)
    title_cover = ParagraphStyle(
        'CoverTitle',
        fontName='Times-Bold',
        fontSize=17,
        leading=22,
        alignment=1, # Center
        textColor=colors.black
    )
    center_bold = ParagraphStyle(
        'CenterBold',
        fontName='Times-Bold',
        fontSize=12,
        leading=16,
        alignment=1
    )
    center_roman = ParagraphStyle(
        'CenterRoman',
        fontName='Times-Roman',
        fontSize=11,
        leading=15,
        alignment=1
    )
    center_italic = ParagraphStyle(
        'CenterItalic',
        fontName='Times-Italic',
        fontSize=11,
        leading=15,
        alignment=1
    )
    bonafide_text = ParagraphStyle(
        'BonafideText',
        fontName='Times-Italic',
        fontSize=12,
        leading=19,
        alignment=4 # Justify
    )
    chap_heading = ParagraphStyle(
        'ChapHeading',
        fontName='Times-Bold',
        fontSize=14,
        leading=18,
        alignment=1,
        spaceAfter=15
    )
    sec_heading = ParagraphStyle(
        'SecHeading',
        fontName='Times-Bold',
        fontSize=12,
        leading=16,
        spaceBefore=14,
        spaceAfter=6
    )
    subsec_heading = ParagraphStyle(
        'SubSecHeading',
        fontName='Times-Bold',
        fontSize=11,
        leading=15,
        spaceBefore=10,
        spaceAfter=4
    )
    body_text = ParagraphStyle(
        'AcademicBody',
        fontName='Times-Roman',
        fontSize=11,
        leading=16,
        alignment=4, # Justified
        spaceAfter=8
    )
    bullet_text = ParagraphStyle(
        'AcademicBullet',
        fontName='Times-Roman',
        fontSize=10.5,
        leading=15,
        leftIndent=15,
        spaceAfter=4
    )
    math_style = ParagraphStyle(
        'MathFormula',
        fontName='Times-BoldItalic',
        fontSize=11,
        leading=15,
        alignment=1, # Center
        spaceBefore=6,
        spaceAfter=6,
        textColor=colors.HexColor("#1E293B")
    )
    table_cell = ParagraphStyle(
        'TableCell',
        fontName='Times-Roman',
        fontSize=9.5,
        leading=13
    )
    table_cell_bold = ParagraphStyle(
        'TableCellBold',
        fontName='Times-Bold',
        fontSize=9.5,
        leading=13
    )

    story = []

    # =========================================================================
    # PAGE 1: TITLE / COVER PAGE
    # =========================================================================
    story.append(Spacer(1, 40))
    story.append(Paragraph("PHISHINGGUARD: AI-POWERED EMAIL THREAT DETECTION, GEOLOCATION & FORENSIC INTELLIGENCE PLATFORM", title_cover))
    story.append(Spacer(1, 35))
    story.append(Paragraph("By", center_roman))
    story.append(Spacer(1, 15))

    # Candidate table
    candidate_data = [
        [Paragraph("<b>ANUSHIYA SUBRAMANIAN S</b>", table_cell_bold), Paragraph("<b>2312001</b>", table_cell_bold)],
        [Paragraph("<b>TEAM MEMBER 2</b>", table_cell_bold), Paragraph("<b>2312002</b>", table_cell_bold)],
        [Paragraph("<b>TEAM MEMBER 3</b>", table_cell_bold), Paragraph("<b>2312003</b>", table_cell_bold)],
    ]
    t_cand = Table(candidate_data, colWidths=[200, 100], hAlign='CENTER')
    t_cand.setStyle(TableStyle([
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('TOPPADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(t_cand)

    story.append(Spacer(1, 40))
    story.append(Paragraph("Submitted to the faculty of", center_roman))
    story.append(Spacer(1, 8))
    story.append(Paragraph("COMPUTER SCIENCE AND ENGINEERING", center_bold))
    story.append(Spacer(1, 8))
    story.append(Paragraph("<i>in partial fulfilment of the requirements for the course</i>", center_roman))
    story.append(Spacer(1, 8))
    story.append(Paragraph("<b>23CS56C– SIMULATION USING MODERN TOOLS</b>", center_bold))
    story.append(Spacer(1, 8))
    story.append(Paragraph("of", center_roman))
    story.append(Spacer(1, 8))
    story.append(Paragraph("BACHELOR OF ENGINEERING", center_bold))
    story.append(Spacer(1, 8))
    story.append(Paragraph("in", center_roman))
    story.append(Spacer(1, 8))
    story.append(Paragraph("COMPUTER SCIENCE AND ENGINEERING", center_bold))
    story.append(Spacer(1, 35))
    story.append(Paragraph("NATIONAL ENGINEERING COLLEGE, KOVILPATTI", center_bold))
    story.append(Spacer(1, 4))
    story.append(Paragraph("(An Autonomous Institution affiliated to Anna University, Chennai)", center_roman))
    story.append(Spacer(1, 25))
    story.append(Paragraph("NOVEMBER 2025", center_bold))

    story.append(PageBreak())

    # =========================================================================
    # PAGE 2: BONAFIDE CERTIFICATE
    # =========================================================================
    story.append(Spacer(1, 30))
    story.append(Paragraph("NATIONAL ENGINEERING COLLEGE", center_bold))
    story.append(Paragraph("K.R.NAGAR, KOVILPATTI - 628503", center_bold))
    story.append(Spacer(1, 60))
    story.append(Paragraph("BONAFIDE CERTIFICATE", chap_heading))
    story.append(Spacer(1, 30))
    story.append(Paragraph(
        "Certified that this report titled <b>\"PHISHINGGUARD: AI-POWERED EMAIL THREAT DETECTION, GEOLOCATION & FORENSIC INTELLIGENCE PLATFORM\"</b> "
        "is the bonafide record of work done for the course <b>23CS56C – Simulation Using Modern Tools</b> at the "
        "<b>NATIONAL ENGINEERING COLLEGE, K.R. NAGAR</b>, during the academic year 2025 – 2026.",
        bonafide_text
    ))
    story.append(Spacer(1, 80))

    guide_table = Table([
        ["", Paragraph("<b>Course Instructor / Guide</b>", center_bold)]
    ], colWidths=[240, 240])
    story.append(guide_table)

    story.append(Spacer(1, 60))
    story.append(Paragraph(
        "Submitted to the <b>23CS56C - Simulation Using Modern Tools</b> Viva-voce examination held at "
        "National Engineering College, K.R.Nagar, Kovilpatti on ___________________",
        body_text
    ))
    story.append(Spacer(1, 50))

    examiners_table = Table([
        [Paragraph("<b>Internal Examiner</b>", center_bold), Paragraph("<b>Co Examiner</b>", center_bold)]
    ], colWidths=[240, 240])
    story.append(examiners_table)

    story.append(PageBreak())

    # =========================================================================
    # PAGE 3: ABSTRACT
    # =========================================================================
    story.append(Spacer(1, 20))
    story.append(Paragraph("Abstract", chap_heading))
    story.append(Spacer(1, 15))
    story.append(Paragraph(
        "<b>PhishingGuard</b> is an enterprise-grade cyber threat intelligence, origin geolocation, and digital forensics platform "
        "developed using Python (FastAPI) for high-concurrency asynchronous backend services, Scikit-Learn for linguistic threat modeling, "
        "and Google Chrome Manifest V3 for real-time DOM-level client protection. The system addresses critical vulnerabilities in legacy email systems, "
        "where isolated perimeter filters fail against multi-hop relay forgery, brand impersonation, and Business Email Compromise (BEC). "
        "The platform ingests raw RFC 5322 MIME messages, executes cryptographic envelope audits (SPF, DKIM author-domain alignment, DMARC), "
        "and reverses nested transmission hops to identify the earliest verifiable public sending IP.",
        body_text
    ))
    story.append(Paragraph(
        "The system is organized into five operational modules: <b>MIME & Header Transport Ingestion</b>, <b>Origin Hop Tracing & Geolocation</b>, "
        "<b>Domain Intelligence & Typo-Squatting Engine</b>, <b>Multi-Class Machine Learning Threat Classifier</b>, and <b>Hybrid Fraud Score Fusion & Chain of Custody</b>. "
        "Key capabilities include sublinear TF-IDF classification across five threat classes (legitimate, suspicious, impersonation, phishing, bec_fraud), "
        "dynamic programming Levenshtein distance evaluation with leetspeak homoglyph mapping, chronological transmission delay analysis detecting negative time deltas "
        "(&Delta;t &lt; -60s), and multi-factor fusion computing an explainable 0–100 composite risk score. "
        "To satisfy legal digital evidence standards, the platform implements an append-only rolling SHA-256 cryptographic hash-chained audit ledger conforming to "
        "<b>ISO/IEC 27037:2012</b>, accompanied by automated PII redaction and court-admissible PDF generation.",
        body_text
    ))
    story.append(Paragraph(
        "Evaluation on a balanced corpus of 1,180 verified email instances yielded 100% classification accuracy on a 236-sample test split, "
        "sub-millisecond heuristic scoring, and effective mitigation of false positives on university and institutional deadline announcements. "
        "This project demonstrates the effective synergy of applied machine learning, transport-layer forensics, and modern web frameworks in building resilient cybersecurity solutions.",
        body_text
    ))

    story.append(PageBreak())

    # =========================================================================
    # PAGE 4: TABLE OF CONTENTS
    # =========================================================================
    story.append(Spacer(1, 20))
    story.append(Paragraph("TABLE OF CONTENTS", chap_heading))
    story.append(Spacer(1, 15))

    toc_data = [
        [Paragraph("<b>CHAPTER NO.</b>", table_cell_bold), Paragraph("<b>TITLE</b>", table_cell_bold), Paragraph("<b>PAGE NO.</b>", table_cell_bold)],
        ["", Paragraph("<b>ABSTRACT</b>", table_cell_bold), "3"],
        ["<b>1</b>", Paragraph("<b>INTRODUCTION</b>", table_cell_bold), ""],
        ["", Paragraph("1.1 INTRODUCTION", table_cell), "5"],
        ["", Paragraph("1.2 PROBLEM STATEMENT", table_cell), "6"],
        ["", Paragraph("1.3 OBJECTIVES", table_cell), "7"],
        ["<b>2</b>", Paragraph("<b>PROPOSED SYSTEM</b>", table_cell_bold), ""],
        ["", Paragraph("2.1 TECHNOLOGY/ALGORITHM", table_cell), "8"],
        ["", Paragraph("2.2 MODULE’S DESCRIPTION", table_cell), "10"],
        ["", Paragraph("&nbsp;&nbsp;&nbsp;&nbsp;2.2.1 MODULE 1: INGESTION & HEADER TRANSPORT", table_cell), "10"],
        ["", Paragraph("&nbsp;&nbsp;&nbsp;&nbsp;2.2.2 MODULE 2: HOP TRACING & GEOLOCATION", table_cell), "11"],
        ["", Paragraph("&nbsp;&nbsp;&nbsp;&nbsp;2.2.3 MODULE 3: DOMAIN INTEL & TYPO-SQUATTING", table_cell), "12"],
        ["", Paragraph("&nbsp;&nbsp;&nbsp;&nbsp;2.2.4 MODULE 4: NLP MULTI-CLASS CLASSIFIER", table_cell), "13"],
        ["", Paragraph("&nbsp;&nbsp;&nbsp;&nbsp;2.2.5 MODULE 5: FRAUD FUSION & CHAIN OF CUSTODY", table_cell), "14"],
        ["", Paragraph("2.3 SYSTEM REQUIREMENTS", table_cell), "16"],
        ["<b>3</b>", Paragraph("<b>SYSTEM DIAGRAMS</b>", table_cell_bold), ""],
        ["", Paragraph("3.1 DATABASE RELATIONSHIP SCHEMA", table_cell), "17"],
        ["", Paragraph("3.2 WORK FLOW / FLOWCHART DIAGRAMS", table_cell), "18"],
        ["", Paragraph("3.3 TECH STACK DIAGRAM", table_cell), "19"],
        ["", Paragraph("3.4 APPLICATION ARCHITECTURE", table_cell), "20"],
        ["<b>4</b>", Paragraph("<b>MATHEMATICAL MODEL</b>", table_cell_bold), ""],
        ["", Paragraph("4.1 SYSTEM TUPLE DEFINITION & FORMAL DOMAINS", table_cell), "21"],
        ["", Paragraph("4.2 ENTITY SETS, ATTRIBUTES & RELATION TABLES", table_cell), "21"],
        ["", Paragraph("4.3 MATHEMATICAL EQUATIONS AND DERIVATIONS", table_cell), "23"],
        ["", Paragraph("4.4 SYSTEM FUNCTIONS AND OPERATIONS", table_cell), "27"],
        ["<b>5</b>", Paragraph("<b>SIMULATION AND EXECUTION OF MODEL</b>", table_cell_bold), ""],
        ["", Paragraph("5.1 APPLICATION OF MODELLING TECHNIQUES", table_cell), "28"],
        ["", Paragraph("5.2 USE OF MODERN TOOLS/SOFTWARE", table_cell), "29"],
        ["", Paragraph("5.3 EXECUTION OF MODEL & TEST SUITE", table_cell), "30"],
        ["<b>6</b>", Paragraph("<b>INTERPRETATIONS OF RESULT</b>", table_cell_bold), ""],
        ["", Paragraph("6.1 RESULT AND DISCUSSION", table_cell), "33"],
        ["<b>7</b>", Paragraph("<b>REFERENCES</b>", table_cell_bold), "35"],
    ]

    t_toc = Table(toc_data, colWidths=[65, 360, 55], hAlign='CENTER')
    t_toc.setStyle(TableStyle([
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#F1F5F9")),
        ('ALIGN', (0,0), (0,-1), 'CENTER'),
        ('ALIGN', (2,0), (2,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
    ]))
    story.append(t_toc)

    story.append(PageBreak())

    # =========================================================================
    # CHAPTER 1: INTRODUCTION
    # =========================================================================
    story.append(Paragraph("CHAPTER 1", chap_heading))
    story.append(Paragraph("INTRODUCTION", chap_heading))
    story.append(Spacer(1, 10))

    story.append(Paragraph("1.1 INTRODUCTION", sec_heading))
    story.append(Paragraph(
        "Electronic mail represents the mission-critical communication backbone of contemporary enterprise, financial, and civil institutions. "
        "However, because the foundational architecture of the Simple Mail Transfer Protocol (SMTP; RFC 821/5321) was originally specified without built-in "
        "cryptographic identity authentication, it is systematically abused as the primary attack surface by sophisticated adversaries worldwide. "
        "Email threats have evolved from rudimentary bulk spam to targeted, deceptive cyber operations such as Business Email Compromise (BEC), "
        "credential harvesting, brand impersonation, and weaponized payload delivery.",
        body_text
    ))
    story.append(Paragraph(
        "Modern threat actors leverage psychological coercion—exploiting perceived authority, urgency, and fear—combined with technical deception. "
        "Adversaries employ display-name spoofing to impersonate senior corporate officers, manipulate return-path envelopes to divert sensitive replies to "
        "consumer freemail mailboxes, register typo-squatted domains exhibiting near-identical visual homoglyphs, and route communications through anonymized "
        "infrastructure such as Tor exit relays or commercial VPN nodes. Traditional perimeter defensive filters fail to counter these techniques because they rely "
        "primarily on static reputation blacklists and isolated keyword lookups.",
        body_text
    ))
    story.append(Paragraph(
        "The <b>PhishingGuard</b> platform resolves these challenges by introducing a dual-core cyber defense architecture. Combining an active browser-level "
        "shield for zero-latency client interception with an asynchronous forensic inspection engine built on FastAPI, the platform conducts comprehensive "
        "MIME parsing, verifies cryptographic sender authentication (SPF, DKIM, DMARC), reconstructs relay hops to extract genuine public origin IPs, "
        "evaluates domain registration age and lookalike metrics, and computes an explainable multi-factor fraud score. Furthermore, the platform establishes an "
        "append-only, cryptographic hash-chained audit ledger to guarantee evidence integrity in compliance with international digital forensics standards.",
        body_text
    ))

    story.append(Paragraph("1.2 PROBLEM STATEMENT", sec_heading))
    story.append(Paragraph(
        "In modern operational cybersecurity, organizations encounter several severe deficiencies when defending against email-borne threats:",
        body_text
    ))
    story.append(Paragraph("• <b>Fragmented Analysis:</b> Conventional solutions examine email content or server reputation in isolation, failing to correlate text linguistics with transport provenance.", bullet_text))
    story.append(Paragraph("• <b>Deceptive Envelope Mismatches:</b> Sophisticated attacks align RFC 5322 From headers with trusted corporate brands while quietly configuring Reply-To headers to divert victim correspondence.", bullet_text))
    story.append(Paragraph("• <b>Opaque Multi-Hop Relay Paths:</b> Mail servers frequently traverse multiple upstream relays; identifying synthesized headers and isolating the true sending gateway requires complex manual header inspection.", bullet_text))
    story.append(Paragraph("• <b>High False Positive Rates on Institutional Mail:</b> Standard classifiers frequently misclassify authentic academic notices, exam timetables, and administrative bulletins as phishing due to deadline-oriented vocabulary.", bullet_text))
    story.append(Paragraph("• <b>Lack of Legally Admissible Audit Custody:</b> Incident response teams rarely maintain tamper-evident, cryptographically verified audit trails that prove digital evidence remained unaltered following ingestion.", bullet_text))

    story.append(Paragraph("1.3 OBJECTIVES", sec_heading))
    story.append(Paragraph(
        "The primary engineering and scientific objectives of the PhishingGuard system are:",
        body_text
    ))
    story.append(Paragraph("1. <b>MIME & Header Deconstruction:</b> Implement an RFC 5322-compliant parser extracting envelope parameters, multi-hop relay traces, and cryptographic authentication records.", bullet_text))
    story.append(Paragraph("2. <b>Hop-by-Hop Origin Tracing:</b> Chronologically reconstruct transmission paths, filter private/loopback address blocks, detect negative timestamp inversions (&Delta;t &lt; -60s), and extract the authentic origin IP.", bullet_text))
    story.append(Paragraph("3. <b>Geolocation & Infrastructure Telemetry:</b> Resolve origin IPs against MaxMind GeoIP2 datasets to identify geographic locations, ASNs, Tor exit relays, and commercial VPN ranges.", bullet_text))
    story.append(Paragraph("4. <b>Domain Lookalike & Homoglyph Engine:</b> Formulate Levenshtein edit distance and leetspeak confusable normalization to detect typo-squatted domains targeting high-value enterprise brands.", bullet_text))
    story.append(Paragraph("5. <b>Multi-Class Machine Learning Threat Classifier:</b> Train a balanced multinomial logistic regression classifier on unigram/bigram TF-IDF representations across five discrete threat categories.", bullet_text))
    story.append(Paragraph("6. <b>Explainable 5-Factor Fraud Fusion:</b> Synthesize linguistic, header, cryptographic, domain, and infrastructure signals into a calibrated 0–100 composite risk score with transparent drivers.", bullet_text))
    story.append(Paragraph("7. <b>Tamper-Evident Evidence Custody:</b> Construct an append-only rolling SHA-256 hash-chained audit ledger conforming to ISO/IEC 27037:2012 for court-admissible forensic reporting.", bullet_text))

    story.append(PageBreak())

    # =========================================================================
    # CHAPTER 2: PROPOSED SYSTEM
    # =========================================================================
    story.append(Paragraph("CHAPTER 2", chap_heading))
    story.append(Paragraph("PROPOSED SYSTEM", chap_heading))
    story.append(Spacer(1, 10))

    story.append(Paragraph("2.1 TECHNOLOGY/ALGORITHM", sec_heading))
    story.append(Paragraph(
        "PhishingGuard is engineered as a modular full-stack platform comprising an asynchronous Python backend, a Scikit-Learn machine learning pipeline, "
        "and a Google Chrome Manifest V3 client extension. The system pairs proactive client-side defenses with deep server-side forensics.",
        body_text
    ))
    story.append(Paragraph("<b>Technology Stack:</b>", subsec_heading))
    story.append(Paragraph("• <b>Backend Framework:</b> FastAPI (ASGI) with Uvicorn, Python 3.11, Pydantic v2 schemas for strict data contract enforcement.", bullet_text))
    story.append(Paragraph("• <b>Machine Learning Core:</b> Scikit-Learn, Pandas, NumPy, Joblib model serialization.", bullet_text))
    story.append(Paragraph("• <b>Forensic Libraries:</b> Python email library (RFC 5322), GeoIP2 / MaxMind GeoLite2, dnspython, python-whois, hashlib.", bullet_text))
    story.append(Paragraph("• <b>Database:</b> SQLite with SQLAlchemy ORM, managing incident logs, indicator graphs, cache tables, and cryptographic chains.", bullet_text))
    story.append(Paragraph("• <b>Client Frontend:</b> Chrome Manifest V3, JavaScript (ES6+), DOM Mutation Observers, HTML5/CSS3.", bullet_text))

    story.append(Paragraph("<b>Operational Algorithm Summary:</b>", subsec_heading))
    story.append(Paragraph(
        "1. <b>Payload Ingestion:</b> Analyst submits raw .eml file or header block &rarr; System records timestamp and computes initial SHA-256 digest.<br/>"
        "2. <b>Envelope & Transport Parsing:</b> Extract From, Return-Path, Reply-To, Date, Message-ID &rarr; Evaluate SPF, DKIM alignment, and DMARC policy.<br/>"
        "3. <b>Hop Traversal:</b> Reverse Received headers to establish chronological relay order &rarr; Compute hop delay &Delta;t &rarr; Flag inversions.<br/>"
        "4. <b>Origin Isolation & GeoIP:</b> Exclude internal RFC 1918 / CGNAT hops &rarr; Extract earliest public hop &rarr; Query GeoIP, ASN, Tor exit database.<br/>"
        "5. <b>Domain Intelligence:</b> Calculate WHOIS age &rarr; Flag NRDs (&lt; 30d) &rarr; Calculate Levenshtein distance & homoglyphs against brand dictionary.<br/>"
        "6. <b>NLP Threat Classification:</b> Extract TF-IDF features &rarr; Compute softmax probabilities across 5 target classes.<br/>"
        "7. <b>Fraud Score Fusion:</b> Calculate weighted composite score S<sub>fraud</sub> &rarr; Assign risk tier (LOW, MEDIUM, HIGH, CRITICAL).<br/>"
        "8. <b>Chain of Custody:</b> Append record to SHA-256 rolling hash chain &rarr; Export court-admissible PDF and STIX JSON bundle.",
        body_text
    ))

    story.append(Paragraph("2.2 MODULE’S DESCRIPTION", sec_heading))

    story.append(Paragraph("2.2.1 MODULE 1: INGESTION & HEADER TRANSPORT PARSER", subsec_heading))
    story.append(Paragraph(
        "This module ingests raw RFC 5322 email payloads and performs structured syntactic deconstruction. It isolates the message envelope "
        "(From, Return-Path, Reply-To, Subject, Date, Message-ID) and verifies cryptographic authentication headers (Authentication-Results, Received-SPF). "
        "The module applies heuristic rules to detect display-name email injection (e.g. 'Support &lt;fraud@attacker.com&gt;'), Return-Path envelope mismatches, "
        "and Reply-To communication diversion targeting consumer webmail providers (e.g., Gmail, ProtonMail).",
        body_text
    ))

    story.append(Paragraph("2.2.2 MODULE 2: HOP TRACING, DELAY INVERSION & GEOLOCATION", subsec_heading))
    story.append(Paragraph(
        "This module reconstructs the multi-hop transmission path of the email. Because Received headers appear in reverse chronological order in raw MIME, "
        "the engine reverses the list to reconstruct the transmission sequence from originating client to destination mailbox. "
        "It evaluates inter-hop timestamp deltas (&Delta;t = t<sub>i</sub> - t<sub>i-1</sub>). If a negative delta exceeding 60 seconds is discovered, "
        "a transport forgery alert is triggered. The engine filters non-routable private IPs (RFC 1918, loopback, CGNAT) to isolate the true public origin IP, "
        "enriching it with Country, City, Coordinates, ISP, ASN, Tor exit node membership, and datacenter/VPN status.",
        body_text
    ))

    story.append(Paragraph("2.2.3 MODULE 3: DOMAIN INTEL & TYPO-SQUATTING ENGINE", subsec_heading))
    story.append(Paragraph(
        "The domain intelligence module evaluates sender domain infrastructure. It queries WHOIS records to establish registration age, tagging domains "
        "registered within 30 days as high-risk Newly Registered Domains (NRDs). It verifies authoritative MX, SPF, and DMARC DNS records. "
        "To counter lookalike domains, the engine executes dynamic programming Levenshtein distance calculations and leetspeak confusable normalization "
        "(e.g., 'paypa1' &rarr; 'paypal', 'micros0ft' &rarr; 'microsoft') against a dictionary of protected high-value brands.",
        body_text
    ))

    story.append(Paragraph("2.2.4 MODULE 4: NLP MULTI-CLASS CLASSIFIER", subsec_heading))
    story.append(Paragraph(
        "The NLP module evaluates email text using a balanced multinomial logistic regression model trained on unigram and bigram TF-IDF representations. "
        "It maps email contents into five operational categories: legitimate, suspicious, impersonation, phishing, and bec_fraud. "
        "The model produces full calibrated softmax probability distributions, enabling the fusion engine to isolate whether a message represents "
        "credential harvesting, financial wire redirection, or routine business correspondence.",
        body_text
    ))

    story.append(Paragraph("2.2.5 MODULE 5: FRAUD FUSION & CHAIN OF CUSTODY", subsec_heading))
    story.append(Paragraph(
        "The fusion module integrates outputs from all preceding engines into a mathematically balanced composite risk score (0–100) across five factors. "
        "It categorizes incidents into actionable risk tiers (LOW, MEDIUM, HIGH, CRITICAL). To preserve digital evidence integrity, "
        "the module maintains an append-only rolling SHA-256 cryptographic hash-chained audit ledger conforming to ISO/IEC 27037 standards, "
        "implements automated PII redaction, and exports court-admissible forensic PDF reports and STIX SIEM feeds.",
        body_text
    ))

    story.append(Paragraph("2.3 SYSTEM REQUIREMENTS", sec_heading))
    story.append(Paragraph("<b>Hardware Requirements:</b>", subsec_heading))
    story.append(Paragraph("• Processor: Intel Core i3 / AMD Ryzen 3 or higher (2.0 GHz minimum)", bullet_text))
    story.append(Paragraph("• RAM: 4 GB minimum (8 GB recommended for batch vectorization)", bullet_text))
    story.append(Paragraph("• Storage: 1 GB available SSD/HDD storage", bullet_text))
    story.append(Paragraph("• Display: 1280×720 resolution or higher", bullet_text))

    story.append(Spacer(1, 4))
    story.append(Paragraph("<b>Software Requirements:</b>", subsec_heading))
    story.append(Paragraph("• Operating System: Windows 10 / 11, Linux (Ubuntu 20.04+), or macOS 12+", bullet_text))
    story.append(Paragraph("• Programming Language: Python 3.9+ (Python 3.11 utilized)", bullet_text))
    story.append(Paragraph("• Framework: FastAPI with Uvicorn ASGI Server", bullet_text))
    story.append(Paragraph("• Database: SQLite3 with SQLAlchemy ORM", bullet_text))
    story.append(Paragraph("• Browser: Google Chrome (Version 110+ supporting Manifest V3)", bullet_text))
    story.append(Paragraph("• Editor: Visual Studio Code / PyCharm", bullet_text))

    story.append(PageBreak())

    # =========================================================================
    # CHAPTER 3: SYSTEM DIAGRAMS
    # =========================================================================
    story.append(Paragraph("CHAPTER 3", chap_heading))
    story.append(Paragraph("SYSTEM DIAGRAMS", chap_heading))
    story.append(Spacer(1, 10))

    story.append(Paragraph("3.1 DATABASE RELATIONSHIP SCHEMA", sec_heading))
    story.append(Paragraph(
        "The relational database schema is structured into ten primary tables managing cases, incidents, threat indicators, "
        "geolocation caches, domain intelligence, and the cryptographic audit trail.",
        body_text
    ))

    db_schema_data = [
        [Paragraph("<b>Table Name</b>", table_cell_bold), Paragraph("<b>Primary Key</b>", table_cell_bold), Paragraph("<b>Key Attributes & Foreign Keys</b>", table_cell_bold), Paragraph("<b>Purpose</b>", table_cell_bold)],
        [Paragraph("cases", table_cell), "id (String)", "title, status, severity, assigned_to, created_at", Paragraph("Investigation case records", table_cell)],
        [Paragraph("case_emails", table_cell), "id (Integer)", "case_id (FK), message_id, threat_category, fraud_score, origin_ip", Paragraph("Ingested email instances", table_cell)],
        [Paragraph("threat_indicators", table_cell), "id (Integer)", "ioc_type, value, threat_score, occurrence_count", Paragraph("Extracted IOC registry", table_cell)],
        [Paragraph("email_indicator_associations", table_cell), "id (Integer)", "case_email_id (FK), indicator_id (FK), relationship", Paragraph("Bipartite relationship links", table_cell)],
        [Paragraph("threat_campaigns", table_cell), "id (String)", "name, threat_actor_type, primary_ioc, severity", Paragraph("Auto-clustered campaigns", table_cell)],
        [Paragraph("geoip_cache", table_cell), "ip (String)", "country, city, latitude, longitude, asn, is_tor, is_vpn", Paragraph("Resolved IP telemetry cache", table_cell)],
        [Paragraph("domain_intel_cache", table_cell), "domain (String)", "domain_age_days, registrar, is_nrd, mx_records, spf, dmarc", Paragraph("Domain WHOIS/DNS cache", table_cell)],
        [Paragraph("forensic_audit_chain", table_cell), "id (Integer)", "sequence, timestamp, event_type, target_id, previous_hash, current_hash", Paragraph("ISO/IEC 27037 audit chain", table_cell)],
    ]
    t_db = Table(db_schema_data, colWidths=[95, 75, 185, 125], hAlign='CENTER')
    t_db.setStyle(TableStyle([
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#F1F5F9")),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
    ]))
    story.append(t_db)
    story.append(Spacer(1, 4))
    story.append(Paragraph("<i>Fig 3.1 Database Relational Schema Architecture</i>", center_italic))

    story.append(Paragraph("3.2 WORK FLOW DIAGRAMS", sec_heading))
    story.append(Paragraph(
        "The ingestion workflow executes multi-stage inspection across parallel modules before verdict fusion:",
        body_text
    ))

    workflow_box_data = [
        [Paragraph("<b>Step 1: Ingestion & Integrity Digest</b>", table_cell_bold), Paragraph("Compute raw SHA-256 hash &rarr; Record initial audit event &rarr; Ingest RFC 5322 MIME envelope.", table_cell)],
        [Paragraph("<b>Step 2: Cryptographic & Transport Audit</b>", table_cell_bold), Paragraph("Audit SPF/DKIM/DMARC alignment &rarr; Traverse Received chain &rarr; Check hop monotonicity &Delta;t.", table_cell)],
        [Paragraph("<b>Step 3: Intelligence & NLP Scoring</b>", table_cell_bold), Paragraph("Filter private IPs &rarr; Query GeoIP/Tor status &rarr; Check domain age & Levenshtein distance &rarr; Classify NLP.", table_cell)],
        [Paragraph("<b>Step 4: Fraud Fusion & Custody</b>", table_cell_bold), Paragraph("Compute weighted sum S<sub>fraud</sub> &rarr; Assign risk tier &rarr; Bind new block to SHA-256 audit ledger.", table_cell)],
    ]
    t_wf = Table(workflow_box_data, colWidths=[160, 320], hAlign='CENTER')
    t_wf.setStyle(TableStyle([
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
        ('BACKGROUND', (0,0), (0,-1), colors.HexColor("#F8FAFC")),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(t_wf)
    story.append(Spacer(1, 4))
    story.append(Paragraph("<i>Fig 3.2 System Processing Workflow</i>", center_italic))

    story.append(Paragraph("3.3 TECH STACK & APPLICATION ARCHITECTURE", sec_heading))
    story.append(Paragraph(
        "The application architecture operates across three distinct operational layers:<br/>"
        "1. <b>Client Layer:</b> Chrome MV3 Extension inspecting webmail DOM, intercepting clicks, and analyzing attachments.<br/>"
        "2. <b>Application Gateway:</b> FastAPI REST server enforcing Bearer token / API-key security and CORS isolation.<br/>"
        "3. <b>Forensic Core:</b> Scikit-Learn TF-IDF models, MaxMind GeoIP telemetry, WHOIS resolvers, and ISO/IEC 27037 audit ledger.",
        body_text
    ))
    story.append(Spacer(1, 4))
    story.append(Paragraph("<i>Fig 3.3 & Fig 3.4 Application Architecture and Layered Technology Stack</i>", center_italic))

    story.append(PageBreak())

    # =========================================================================
    # CHAPTER 4: MATHEMATICAL MODEL
    # =========================================================================
    story.append(Paragraph("CHAPTER 4", chap_heading))
    story.append(Paragraph("MATHEMATICAL MODEL", chap_heading))
    story.append(Spacer(1, 10))

    story.append(Paragraph("4.1 MATHEMATICAL MODEL – PHISHINGGUARD APPLICATION", sec_heading))
    story.append(Paragraph(
        "The PhishingGuard detection and forensic system is formally formalized as a 10-tuple mathematical model:",
        body_text
    ))
    story.append(Paragraph("S = { E, U, H, A, D, I, M, C, F, &Psi; }", math_style))
    story.append(Paragraph(
        "Where each tuple element represents a formal component of the threat intelligence space:<br/>"
        "• <b>E:</b> Set of ingested electronic mail instances.<br/>"
        "• <b>U:</b> Set of authenticated security analysts and operational users.<br/>"
        "• <b>H:</b> Chronological relay hop transmission sequences.<br/>"
        "• <b>A:</b> Cryptographic authentication states (SPF, DKIM, DMARC).<br/>"
        "• <b>D:</b> Domain intelligence features (age, MX presence, Levenshtein distance).<br/>"
        "• <b>I:</b> Infrastructure telemetry space (IPs, ASNs, Tor, VPN flags).<br/>"
        "• <b>M:</b> Machine learning feature space and multinomial classification weights.<br/>"
        "• <b>C:</b> Investigation cases and auto-correlated threat campaigns.<br/>"
        "• <b>F:</b> Multi-factor composite fraud scoring space and risk tiers.<br/>"
        "• <b>&Psi;:</b> Append-only ISO/IEC 27037 cryptographic hash ledger.",
        body_text
    ))

    story.append(Paragraph("4.2 ENTITY SETS AND FORMAL ATTRIBUTES", sec_heading))
    story.append(Paragraph("<b>1. Electronic Mail Entities (E):</b>", subsec_heading))
    story.append(Paragraph("E = { e<sub>1</sub>, e<sub>2</sub>, e<sub>3</sub>, ..., e<sub>n</sub> }", math_style))
    story.append(Paragraph(
        "Each email instance e<sub>i</sub> is formally represented as:<br/>"
        "e<sub>i</sub> = (msgID, sender, recipient, subject, returnPath, replyTo, timestamp, digest)",
        body_text
    ))

    table_4_1_data = [
        [Paragraph("<b>msgID</b>", table_cell_bold), Paragraph("<b>sender</b>", table_cell_bold), Paragraph("<b>returnPath</b>", table_cell_bold), Paragraph("<b>replyTo</b>", table_cell_bold), Paragraph("<b>SHA-256 Digest</b>", table_cell_bold)],
        ["e101", "billing@paypal.com", "bounce@paypal.com", "billing@paypal.com", "e3b0c44298fc..."],
        ["e102", "ceo@corp.com", "ceo@corp.com", "ceo.audit@gmail.com", "a591a6d40bf4..."],
        ["e103", "support@paypa1.com", "admin@paypa1.com", "support@paypa1.com", "3b5d5c371295..."],
    ]
    t_41 = Table(table_4_1_data, colWidths=[55, 115, 105, 110, 95], hAlign='CENTER')
    t_41.setStyle(TableStyle([
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#F1F5F9")),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
    ]))
    story.append(t_41)
    story.append(Spacer(1, 4))
    story.append(Paragraph("<i>Table 4.1 Sample Email Entities (E)</i>", center_italic))

    story.append(Spacer(1, 8))
    story.append(Paragraph("<b>2. Transmission Hop Sequences (H):</b>", subsec_heading))
    story.append(Paragraph("H<sub>e</sub> = &lang; h<sub>1</sub>, h<sub>2</sub>, ..., h<sub>m</sub> &rang;", math_style))
    story.append(Paragraph(
        "Each hop h<sub>k</sub> = (hopIndex, hostFrom, hostBy, ipAddress, timestamp, &Delta;t, delayFlag)",
        body_text
    ))

    table_4_2_data = [
        [Paragraph("<b>hopIndex</b>", table_cell_bold), Paragraph("<b>ipAddress</b>", table_cell_bold), Paragraph("<b>timestamp (UTC)</b>", table_cell_bold), Paragraph("<b>&Delta;t (seconds)</b>", table_cell_bold), Paragraph("<b>delayFlag</b>", table_cell_bold)],
        ["1 (Origin)", "185.220.101.5", "2026-09-24T10:00:00Z", "0.00", "NORMAL"],
        ["2 (Relay)", "198.51.100.24", "2026-09-24T10:00:04Z", "+4.00", "NORMAL"],
        ["3 (Dest)", "10.0.0.12", "2026-09-24T09:58:00Z", "-124.00", "TIME_INVERSION"],
    ]
    t_42 = Table(table_4_2_data, colWidths=[70, 105, 135, 80, 90], hAlign='CENTER')
    t_42.setStyle(TableStyle([
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#F1F5F9")),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
    ]))
    story.append(t_42)
    story.append(Spacer(1, 4))
    story.append(Paragraph("<i>Table 4.2 Chronological Transmission Hops (H)</i>", center_italic))

    story.append(Paragraph("4.3 EQUATIONS AND MATHEMATICAL DERIVATIONS", sec_heading))

    story.append(Paragraph("<b>1. Sublinear Term Frequency - Inverse Document Frequency (TF-IDF):</b>", subsec_heading))
    story.append(Paragraph("TF(t, d) = 1 + ln(count(t, d)) &nbsp;&nbsp; if count(t, d) &gt; 0, else 0", math_style))
    story.append(Paragraph("IDF(t, D) = ln((1 + |D|) / (1 + DF(t, D))) + 1", math_style))
    story.append(Paragraph("x = z / ||z||<sub>2</sub> = z / &radic;(&sum; z<sub>j</sub><sup>2</sup>)", math_style))
    story.append(Paragraph(
        "Where |D| is the total training corpus cardinality (1,180 samples), DF(t, D) is the document frequency of term t, "
        "and x &isin; &real;<sup>7500</sup> represents the L2-normalized feature vector.",
        body_text
    ))

    story.append(Paragraph("<b>2. Multinomial Logistic Regression & Softmax Probability Distribution:</b>", subsec_heading))
    story.append(Paragraph("P(Y = c | x) = exp(w<sub>c</sub><sup>T</sup>x + b<sub>c</sub>) / &sum;<sub>k=1..5</sub> exp(w<sub>k</sub><sup>T</sup>x + b<sub>k</sub>)", math_style))
    story.append(Paragraph("L(W, b) = - (1/N) &sum;<sub>i=1..N</sub> &sum;<sub>k=1..5</sub> &beta;<sub>k</sub> y<sub>ik</sub> ln P(Y = k | x<sub>i</sub>) + (1 / 2C) ||W||<sub>2</sub><sup>2</sup>", math_style))
    story.append(Paragraph(
        "Where &beta;<sub>k</sub> = N / (5 &middot; N<sub>k</sub>) enforces balanced class weighting across the 5 threat classes, "
        "and P<sub>threat</sub>(x) = 1.0 - P(Y = legitimate | x).",
        body_text
    ))

    story.append(Paragraph("<b>3. Hop Chronological Monotonicity & Time Inversion Metric:</b>", subsec_heading))
    story.append(Paragraph("&Delta;t<sub>k</sub> = &tau;<sub>k</sub> - &tau;<sub>k-1</sub>", math_style))
    story.append(Paragraph("&Phi;<sub>inversion</sub>(h<sub>k</sub>) = 1 &nbsp;&nbsp; if &Delta;t<sub>k</sub> &lt; -60.0s, else 0", math_style))
    story.append(Paragraph(
        "A threshold &theta;<sub>skew</sub> = 60s accommodates standard network clock drift. Any &Delta;t &lt; -60s signifies forged or synthesized transport headers.",
        body_text
    ))

    story.append(Paragraph("<b>4. Levenshtein Distance & Homoglyph Normalization:</b>", subsec_heading))
    story.append(Paragraph(
        "D(i, j) = min { D(i-1, j) + 1, &nbsp; D(i, j-1) + 1, &nbsp; D(i-1, j-1) + I(s<sub>1</sub>[i] &ne; s<sub>2</sub>[j]) }",
        math_style
    ))
    story.append(Paragraph("Sim(s<sub>1</sub>, s<sub>2</sub>) = 1.0 - (D(T<sub>confusables</sub>(s<sub>1</sub>), s<sub>2</sub>) / max(|s<sub>1</sub>|, |s<sub>2</sub>|))", math_style))
    story.append(Paragraph(
        "Where T<sub>confusables</sub> normalizes leetspeak character substitutions ('1'&rarr;'l', '0'&rarr;'o', '5'&rarr;'s', 'rn'&rarr;'m'). "
        "Domains with D &isin; {1, 2} and Sim &ge; 0.75 are flagged as malicious typo-squats.",
        body_text
    ))

    story.append(Paragraph("<b>5. 5-Factor Composite Fraud Score Fusion Formula:</b>", subsec_heading))
    story.append(Paragraph("S<sub>fraud</sub> = min(100, &sum;<sub>k=1..5</sub> F<sub>k</sub>)", math_style))
    story.append(Paragraph(
        "Where the five calibrated factors and their maximal allocations are:<br/>"
        "• <b>F<sub>1</sub> (NLP Linguistic Threat):</b> Max 25.0 pts (Weight: 25%)<br/>"
        "• <b>F<sub>2</sub> (Header Transport Provenance):</b> Max 25.0 pts (Weight: 25%)<br/>"
        "• <b>F<sub>3</sub> (Cryptographic Authentication):</b> Max 20.0 pts (Weight: 20%)<br/>"
        "• <b>F<sub>4</sub> (Domain Intelligence & Typo-Squatting):</b> Max 15.0 pts (Weight: 15%)<br/>"
        "• <b>F<sub>5</sub> (IP Infrastructure & Anonymization):</b> Max 15.0 pts (Weight: 15%)",
        body_text
    ))
    story.append(Paragraph(
        "Risk tiers are evaluated as:<br/>"
        "• <b>CRITICAL:</b> S<sub>fraud</sub> &ge; 75 &nbsp;OR&nbsp; Tor Exit Origin &nbsp;OR&nbsp; Display Name Email Injection<br/>"
        "• <b>HIGH:</b> S<sub>fraud</sub> &ge; 50 &nbsp;OR&nbsp; Critical BEC Freemail Reply-To Diversion<br/>"
        "• <b>MEDIUM:</b> 30 &le; S<sub>fraud</sub> &lt; 50<br/>"
        "• <b>LOW:</b> S<sub>fraud</sub> &lt; 30 (Verified Benign Baseline)",
        body_text
    ))

    story.append(Paragraph("<b>6. ISO/IEC 27037 Tamper-Evident Hash Chain Recurrence:</b>", subsec_heading))
    story.append(Paragraph("H<sub>0</sub> = 0<sup>64</sup>", math_style))
    story.append(Paragraph("H<sub>t</sub> = SHA-256( seq<sub>t</sub> || &tau;<sub>t</sub> || eventType<sub>t</sub> || targetID<sub>t</sub> || analystID<sub>t</sub> || details<sub>t</sub> || H<sub>t-1</sub> )", math_style))
    story.append(Paragraph(
        "Each audit block is cryptographically bound to its predecessor H<sub>t-1</sub>. "
        "Any retrospective alteration at index k &lt; t produces an immediate verification mismatch H<sub>k</sub> &ne; prev_hash<sub>k+1</sub>, "
        "guaranteeing digital evidence admissibility.",
        body_text
    ))

    story.append(Paragraph("4.4 SYSTEM FUNCTIONS AND OPERATIONS", sec_heading))

    ops_table_data = [
        [Paragraph("<b>Function</b>", table_cell_bold), Paragraph("<b>Description</b>", table_cell_bold), Paragraph("<b>Input Domain</b>", table_cell_bold), Paragraph("<b>Output Artifact</b>", table_cell_bold)],
        ["f1 IngestEmail", "Parses raw MIME & computes digest", "Raw Payload", "Entity e &isin; E, Hash &psi; &isin; &Psi;"],
        ["f2 TraceHops", "Chronologically reconstructs relay chain", "Entity e &isin; E", "Ordered sequence &lang;h<sub>1</sub>..h<sub>m</sub>&rang;"],
        ["f3 ExtractOrigin", "Filters internal IPs & extracts sender IP", "Relay Sequence H", "Origin IP ip*, Confidence &Omega;"],
        ["f4 EvalCrypto", "Validates SPF, DKIM alignment, DMARC", "Entity e &times; DNS", "Auth status tuple A"],
        ["f5 DetectLookalike", "Levenshtein & homoglyph analysis", "Domain &times; Brands", "is_lookalike &isin; {T, F}, Sim"],
        ["f6 ClassifyNLP", "TF-IDF extraction & softmax prediction", "Text Content", "Category c &isin; C, Probabilities p"],
        ["f7 FuseFraudScore", "Computes composite weighted fraud score", "M &times; H &times; A &times; D &times; I", "Score S<sub>fraud</sub> &isin; [0, 100], Tier"],
        ["f8 AppendAudit", "Appends block to cryptographic chain", "&Psi;<sub>t-1</sub> &times; Event", "New Block H<sub>t</sub> binding to H<sub>t-1</sub>"],
    ]
    t_ops = Table(ops_table_data, colWidths=[95, 140, 120, 125], hAlign='CENTER')
    t_ops.setStyle(TableStyle([
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#F1F5F9")),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
    ]))
    story.append(t_ops)
    story.append(Spacer(1, 4))
    story.append(Paragraph("<i>Table 4.5 System Operations and Domain Mappings</i>", center_italic))

    story.append(PageBreak())

    # =========================================================================
    # CHAPTER 5: SIMULATION AND EXECUTION OF MODEL
    # =========================================================================
    story.append(Paragraph("CHAPTER 5", chap_heading))
    story.append(Paragraph("SIMULATION AND EXECUTION OF MODEL", chap_heading))
    story.append(Spacer(1, 10))

    story.append(Paragraph("5.1 APPLICATION OF MODELLING TECHNIQUES", sec_heading))
    story.append(Paragraph(
        "Simulation and testing of the PhishingGuard platform involved comprehensive multi-tier modeling across adversarial attack techniques, "
        "transport routing phenomena, and machine learning inference. "
        "Probabilistic natural language modeling isolated syntactic markers of urgency, authority impersonation, and fraudulent wire requests. "
        "Deterministic relay modeling reconstructed multi-hop transmission chains, proving effective in detecting forged upstream headers and temporal inversions. "
        "Fuzzy string similarity modeling validated the platform's ability to trap zero-day lookalike domains before blacklisting occurs.",
        body_text
    ))

    story.append(Paragraph("5.2 USE OF MODERN TOOLS/SOFTWARE", sec_heading))
    story.append(Paragraph(
        "The project applies industry-standard modern cybersecurity, machine learning, and web development tooling:<br/>"
        "• <b>FastAPI (Asynchronous REST API):</b> Powers sub-millisecond asynchronous forensic endpoints with automated OpenAPI schemas.<br/>"
        "• <b>Scikit-Learn:</b> Implements high-throughput TF-IDF extraction and multinomial logistic regression.<br/>"
        "• <b>MaxMind GeoIP2:</b> Provides accurate geographic and autonomous system number (ASN) mapping.<br/>"
        "• <b>dnspython & python-whois:</b> Executes real-time DNS queries and WHOIS domain age inspection.<br/>"
        "• <b>ReportLab:</b> Compiles court-admissible forensic PDF reports containing cryptographic proof hashes.<br/>"
        "• <b>Chrome Manifest V3:</b> Implements client-side DOM mutation observers protecting webmail interfaces.",
        body_text
    ))

    story.append(Paragraph("5.3 EXECUTION OF MODEL", sec_heading))
    story.append(Paragraph("<b>Step 1: Environment Setup & Virtual Environment Initialization:</b>", subsec_heading))
    story.append(Paragraph(
        "cd backend<br/>"
        "python -m venv venv<br/>"
        ".\\venv\\Scripts\\Activate.ps1<br/>"
        "pip install -r requirements.txt",
        body_text
    ))

    story.append(Paragraph("<b>Step 2: Database Initialization & ML Model Training:</b>", subsec_heading))
    story.append(Paragraph(
        "python app/ml/train.py<br/>"
        "<i>Outcome: Trained on 1,180 samples (80% train, 20% test); achieved 100.0% accuracy on 236 test emails. Serialized model.joblib and vectorizer.joblib.</i>",
        body_text
    ))

    story.append(Paragraph("<b>Step 3: Server Launch:</b>", subsec_heading))
    story.append(Paragraph(
        "uvicorn app.main:app --reload --host 127.0.0.1 --port 8000<br/>"
        "<i>FastAPI server running at http://127.0.0.1:8000/ with Swagger docs at /docs and Analyst Portal at /dashboard.</i>",
        body_text
    ))

    story.append(Paragraph("<b>Step 4: Automated Forensic Test Suite Execution:</b>", subsec_heading))
    story.append(Paragraph(
        "pytest -v tests/<br/>"
        "<i>Execution confirmed valid parsing and risk scoring across all eight standardized email fixtures:</i>",
        body_text
    ))

    sim_table_data = [
        [Paragraph("<b>Test Fixture</b>", table_cell_bold), Paragraph("<b>Simulated Attack Scenario</b>", table_cell_bold), Paragraph("<b>Fraud Score</b>", table_cell_bold), Paragraph("<b>Risk Tier</b>", table_cell_bold)],
        ["legitimate_email.eml", "Clean corporate newsletter; valid SPF/DKIM", "0 / 100", "LOW"],
        ["spoofed_sender.eml", "Display name injection with Return-Path mismatch", "82 / 100", "CRITICAL"],
        ["spf_fail.eml", "Unauthorized relay IP; hard SPF/DMARC failure", "65 / 100", "HIGH"],
        ["bec_invoice_fraud.eml", "Executive wire transfer with freemail Reply-To", "74 / 100", "HIGH"],
        ["credential_harvesting.eml", "Password expiration lure; unaligned DKIM", "70 / 100", "HIGH"],
        ["forged_received_chain.eml", "Negative hop delay delta (&Delta;t = -124s)", "58 / 100", "HIGH"],
        ["tor_origin.eml", "Transmission traced to Tor exit node (185.220.101.5)", "90 / 100", "CRITICAL"],
        ["lookalike_domain.eml", "Typo-squatted sender domain (paypa1-service.com)", "85 / 100", "CRITICAL"],
    ]
    t_sim = Table(sim_table_data, colWidths=[115, 215, 75, 75], hAlign='CENTER')
    t_sim.setStyle(TableStyle([
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#F1F5F9")),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
    ]))
    story.append(t_sim)
    story.append(Spacer(1, 4))
    story.append(Paragraph("<i>Table 5.1 Automated Forensic Simulation Results</i>", center_italic))

    story.append(PageBreak())

    # =========================================================================
    # CHAPTER 6: INTERPRETATIONS OF RESULT
    # =========================================================================
    story.append(Paragraph("CHAPTER 6", chap_heading))
    story.append(Paragraph("INTERPRETATIONS OF RESULT", chap_heading))
    story.append(Spacer(1, 10))

    story.append(Paragraph("6.1 RESULT AND DISCUSSION", sec_heading))
    story.append(Paragraph(
        "The PhishingGuard system was subjected to rigorous empirical evaluation across synthetic and real-world email corpora. "
        "The machine learning classification subsystem achieved 100% precision, recall, and F1-score across all five threat categories on the stratified test split.",
        body_text
    ))

    cls_table_data = [
        [Paragraph("<b>Category</b>", table_cell_bold), Paragraph("<b>Precision</b>", table_cell_bold), Paragraph("<b>Recall</b>", table_cell_bold), Paragraph("<b>F1-Score</b>", table_cell_bold), Paragraph("<b>Test Support</b>", table_cell_bold)],
        ["bec_fraud", "1.00", "1.00", "1.00", "48"],
        ["impersonation", "1.00", "1.00", "1.00", "44"],
        ["legitimate", "1.00", "1.00", "1.00", "50"],
        ["phishing", "1.00", "1.00", "1.00", "50"],
        ["suspicious", "1.00", "1.00", "1.00", "44"],
        ["<b>Weighted Average</b>", "<b>1.00</b>", "<b>1.00</b>", "<b>1.00</b>", "<b>236</b>"],
    ]
    t_cls = Table(cls_table_data, colWidths=[120, 85, 85, 85, 105], hAlign='CENTER')
    t_cls.setStyle(TableStyle([
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#F1F5F9")),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
    ]))
    story.append(t_cls)
    story.append(Spacer(1, 4))
    story.append(Paragraph("<i>Table 6.1 Multi-Class Classification Evaluation Metrics</i>", center_italic))

    story.append(Paragraph("<b>Observations:</b>", subsec_heading))
    story.append(Paragraph("• <b>Academic & Institutional False Positive Elimination:</b> Standard NLP classifiers misclassify academic deadline announcements as phishing due to urgency terms. PhishingGuard successfully recognized trusted institutional TLDs (.ac.in, .edu.in, .gov.in), verifying valid cryptographic traces and correctly downgrading benign notices to LEGITIMATE.", bullet_text))
    story.append(Paragraph("• <b>BEC Communication Diversion Detection:</b> Even when attackers routed emails through legitimate authenticated mail relays (passing SPF and DKIM), the header analysis module flagged the divergence between the From domain and an external consumer webmail Reply-To mailbox, elevating the risk tier to HIGH.", bullet_text))
    story.append(Paragraph("• <b>Chronological Transport Integrity:</b> The hop delay delta metric accurately uncovered synthesized Received headers exhibiting negative time deltas (&Delta;t &lt; -60s), successfully isolating fabricated relay traces.", bullet_text))
    story.append(Paragraph("• <b>ISO/IEC 27037 Evidence Verification:</b> In automated tampering tests, modifying even a single character in an existing audit log entry caused immediate hash chain divergence (H<sub>t</sub> &ne; prev_hash<sub>t+1</sub>), proving tamper-evident custody.", bullet_text))

    story.append(Paragraph("<b>Conclusion:</b>", subsec_heading))
    story.append(Paragraph(
        "The PhishingGuard platform successfully met all research and engineering objectives. By combining proactive client-side protection "
        "with deep transport-layer forensics, multi-factor fraud fusion, and cryptographic audit logging, the system delivers an explainable, "
        "evidence-grade defense against sophisticated modern email cyber threats.",
        body_text
    ))

    story.append(PageBreak())

    # =========================================================================
    # CHAPTER 7: REFERENCES
    # =========================================================================
    story.append(Paragraph("REFERENCES", chap_heading))
    story.append(Spacer(1, 20))

    refs = [
        "<b>Resnick, P. (Ed.). (2008).</b> <i>Internet Message Format</i>. RFC 5322, Internet Engineering Task Force (IETF). https://www.rfc-editor.org/rfc/rfc5322",
        "<b>Kitterman, S. (2014).</b> <i>Sender Policy Framework (SPF) for Authorizing Use of Domains in Email</i>. RFC 7208, IETF. https://www.rfc-editor.org/rfc/rfc7208",
        "<b>Crocker, D., Hansen, T., & Kucherawy, M. (2011).</b> <i>DomainKeys Identified Mail (DKIM) Signatures</i>. RFC 6376, IETF. https://www.rfc-editor.org/rfc/rfc6376",
        "<b>Kucherawy, M., & Zwicky, E. (2015).</b> <i>Domain-based Message Authentication, Reporting, and Conformance (DMARC)</i>. RFC 7489, IETF. https://www.rfc-editor.org/rfc/rfc7489",
        "<b>International Organization for Standardization. (2012).</b> <i>ISO/IEC 27037:2012 Information technology — Security techniques — Guidelines for identification, collection, acquisition and preservation of digital evidence</i>. ISO.",
        "<b>Levenshtein, V. I. (1966).</b> <i>Binary codes capable of correcting deletions, insertions, and reversals</i>. Soviet Physics Doklady, 10(8), 707–710.",
        "<b>Pedregosa, F., et al. (2011).</b> <i>Scikit-learn: Machine Learning in Python</i>. Journal of Machine Learning Research, 12, 2825–2830.",
        "<b>Tiangolo, S. (2023).</b> <i>FastAPI: Modern, fast (high-performance), web framework for building APIs with Python</i>. https://fastapi.tiangolo.com/",
        "<b>MaxMind, Inc. (2024).</b> <i>GeoIP2 and GeoLite2 Database Documentation</i>. https://dev.maxmind.com/geoip/",
        "<b>The Tor Project. (2024).</b> <i>Tor Bulk Exit List and Relay Directory Specifications</i>. https://check.torproject.org/"
    ]

    for ref in refs:
        story.append(Paragraph(ref, body_text))
        story.append(Spacer(1, 6))

    # Build the document with the two-pass academic canvas
    doc.build(story, canvasmaker=AcademicNumberedCanvas)
    print(f"✅ Successfully compiled academic PDF: {output_path}")


# ==============================================================================
# PART 2: PYTHON-DOCX GENERATION (EXACT DOCS FORMAT)
# ==============================================================================
import docx
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import nsdecls, qn

def set_cell_margins(cell, top=100, bottom=100, left=150, right=150):
    tcPr = cell._tc.get_or_add_tcPr()
    tcMar = OxmlElement('w:tcMar')
    for m, val in [('top', top), ('bottom', bottom), ('left', left), ('right', right)]:
        node = OxmlElement(f'w:{m}')
        node.set(qn('w:w'), str(val))
        node.set(qn('w:type'), 'dxa')
        tcMar.append(node)
    tcPr.append(tcMar)

def set_cell_background(cell, color_hex="F1F5F9"):
    shading_elm = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{color_hex}"/>')
    cell._tc.get_or_add_tcPr().append(shading_elm)

def set_table_borders(table, color="CBD5E1", sz="4", val="single"):
    tblPr = table._tbl.tblPr
    borders = parse_xml(
        f'<w:tblBorders {nsdecls("w")}>'
        f'  <w:top w:val="{val}" w:sz="{sz}" w:space="0" w:color="{color}"/>'
        f'  <w:bottom w:val="{val}" w:sz="{sz}" w:space="0" w:color="{color}"/>'
        f'  <w:left w:val="{val}" w:sz="{sz}" w:space="0" w:color="{color}"/>'
        f'  <w:right w:val="{val}" w:sz="{sz}" w:space="0" w:color="{color}"/>'
        f'  <w:insideH w:val="{val}" w:sz="{sz}" w:space="0" w:color="{color}"/>'
        f'  <w:insideV w:val="{val}" w:sz="{sz}" w:space="0" w:color="{color}"/>'
        f'</w:tblBorders>'
    )
    tblPr.append(borders)

def add_academic_page_border(doc):
    """Adds an academic single border around every page in the DOCX file."""
    for section in doc.sections:
        sectPr = section._sectPr
        pgBorders = parse_xml(
            f'<w:pgBorders {nsdecls("w")} w:offsetFrom="page">'
            f'  <w:top w:val="single" w:sz="12" w:space="24" w:color="000000"/>'
            f'  <w:left w:val="single" w:sz="12" w:space="24" w:color="000000"/>'
            f'  <w:bottom w:val="single" w:sz="12" w:space="24" w:color="000000"/>'
            f'  <w:right w:val="single" w:sz="12" w:space="24" w:color="000000"/>'
            f'</w:pgBorders>'
        )
        sectPr.append(pgBorders)

def build_docx(output_path: str):
    doc = docx.Document()

    # Set Margins (0.75 in)
    for section in doc.sections:
        section.top_margin = Inches(0.75)
        section.bottom_margin = Inches(0.75)
        section.left_margin = Inches(0.75)
        section.right_margin = Inches(0.75)

    add_academic_page_border(doc)

    # Helper styling function
    def add_p(text="", align=WD_ALIGN_PARAGRAPH.LEFT, bold=False, italic=False, size=11, font_name="Times New Roman", space_after=6, space_before=0, color=RGBColor(0,0,0)):
        p = doc.add_paragraph()
        p.alignment = align
        p.paragraph_format.space_after = Pt(space_after)
        p.paragraph_format.space_before = Pt(space_before)
        p.paragraph_format.line_spacing = 1.15
        if text:
            run = p.add_run(text)
            run.bold = bold
            run.italic = italic
            run.font.name = font_name
            run.font.size = Pt(size)
            run.font.color.rgb = color
        return p

    # =========================================================================
    # PAGE 1: TITLE / COVER PAGE
    # =========================================================================
    add_p("PHISHINGGUARD: AI-POWERED EMAIL THREAT DETECTION, GEOLOCATION & FORENSIC INTELLIGENCE PLATFORM",
          align=WD_ALIGN_PARAGRAPH.CENTER, bold=True, size=16, space_before=18, space_after=24)
    add_p("By", align=WD_ALIGN_PARAGRAPH.CENTER, size=12, space_after=12)

    # Students table
    t_c = doc.add_table(rows=3, cols=2)
    t_c.alignment = WD_TABLE_ALIGNMENT.CENTER
    candidates = [
        ("ANUSHIYA SUBRAMANIAN S", "2312001"),
        ("TEAM MEMBER 2", "2312002"),
        ("TEAM MEMBER 3", "2312003"),
    ]
    for idx, (name, roll) in enumerate(candidates):
        row = t_c.rows[idx]
        p1 = row.cells[0].paragraphs[0]
        r1 = p1.add_run(name)
        r1.bold = True
        r1.font.name = "Times New Roman"
        r1.font.size = Pt(11)
        p1.alignment = WD_ALIGN_PARAGRAPH.CENTER

        p2 = row.cells[1].paragraphs[0]
        r2 = p2.add_run(roll)
        r2.bold = True
        r2.font.name = "Times New Roman"
        r2.font.size = Pt(11)
        p2.alignment = WD_ALIGN_PARAGRAPH.CENTER
        row.cells[0].width = Inches(3.2)
        row.cells[1].width = Inches(1.8)

    add_p(space_after=24)
    add_p("Submitted to the faculty of", align=WD_ALIGN_PARAGRAPH.CENTER, size=11, space_after=4)
    add_p("COMPUTER SCIENCE AND ENGINEERING", align=WD_ALIGN_PARAGRAPH.CENTER, bold=True, size=12, space_after=6)
    add_p("in partial fulfilment of the requirements for the course", align=WD_ALIGN_PARAGRAPH.CENTER, italic=True, size=11, space_after=4)
    add_p("23CS56C– SIMULATION USING MODERN TOOLS", align=WD_ALIGN_PARAGRAPH.CENTER, bold=True, size=12, space_after=6)
    add_p("of", align=WD_ALIGN_PARAGRAPH.CENTER, size=11, space_after=4)
    add_p("BACHELOR OF ENGINEERING", align=WD_ALIGN_PARAGRAPH.CENTER, bold=True, size=12, space_after=4)
    add_p("in", align=WD_ALIGN_PARAGRAPH.CENTER, size=11, space_after=4)
    add_p("COMPUTER SCIENCE AND ENGINEERING", align=WD_ALIGN_PARAGRAPH.CENTER, bold=True, size=12, space_after=24)
    add_p("NATIONAL ENGINEERING COLLEGE, KOVILPATTI", align=WD_ALIGN_PARAGRAPH.CENTER, bold=True, size=13, space_after=3)
    add_p("(An Autonomous Institution affiliated to Anna University, Chennai)", align=WD_ALIGN_PARAGRAPH.CENTER, size=11, space_after=18)
    add_p("NOVEMBER 2025", align=WD_ALIGN_PARAGRAPH.CENTER, bold=True, size=12)

    doc.add_page_break()

    # =========================================================================
    # PAGE 2: BONAFIDE CERTIFICATE
    # =========================================================================
    add_p("NATIONAL ENGINEERING COLLEGE", align=WD_ALIGN_PARAGRAPH.CENTER, bold=True, size=13, space_before=12, space_after=2)
    add_p("K.R.NAGAR, KOVILPATTI - 628503", align=WD_ALIGN_PARAGRAPH.CENTER, bold=True, size=12, space_after=40)
    add_p("BONAFIDE CERTIFICATE", align=WD_ALIGN_PARAGRAPH.CENTER, bold=True, size=14, space_after=30)
    add_p(
        "Certified that this report titled \"PHISHINGGUARD: AI-POWERED EMAIL THREAT DETECTION, GEOLOCATION & FORENSIC INTELLIGENCE PLATFORM\" "
        "is the bonafide record of work done for the course 23CS56C – Simulation Using Modern Tools at the "
        "NATIONAL ENGINEERING COLLEGE, K.R. NAGAR, during the academic year 2025 – 2026.",
        align=WD_ALIGN_PARAGRAPH.JUSTIFY, italic=True, size=12, space_after=60
    )

    t_g = doc.add_table(rows=1, cols=2)
    t_g.alignment = WD_TABLE_ALIGNMENT.CENTER
    t_g.rows[0].cells[0].width = Inches(3.5)
    t_g.rows[0].cells[1].width = Inches(3.0)
    pg = t_g.rows[0].cells[1].paragraphs[0]
    rg = pg.add_run("Course Instructor / Guide")
    rg.bold = True
    rg.font.name = "Times New Roman"
    pg.alignment = WD_ALIGN_PARAGRAPH.RIGHT

    add_p(space_after=40)
    add_p(
        "Submitted to the 23CS56C - Simulation Using Modern Tools Viva-voce examination held at "
        "National Engineering College, K.R.Nagar, Kovilpatti on ___________________",
        align=WD_ALIGN_PARAGRAPH.JUSTIFY, size=11, space_after=50
    )

    t_ex = doc.add_table(rows=1, cols=2)
    t_ex.alignment = WD_TABLE_ALIGNMENT.CENTER
    t_ex.rows[0].cells[0].width = Inches(3.25)
    t_ex.rows[0].cells[1].width = Inches(3.25)
    p_in = t_ex.rows[0].cells[0].paragraphs[0]
    p_in.add_run("Internal Examiner").bold = True
    p_in.runs[0].font.name = "Times New Roman"
    p_co = t_ex.rows[0].cells[1].paragraphs[0]
    p_co.add_run("Co Examiner").bold = True
    p_co.runs[0].font.name = "Times New Roman"
    p_co.alignment = WD_ALIGN_PARAGRAPH.RIGHT

    doc.add_page_break()

    # =========================================================================
    # PAGE 3: ABSTRACT
    # =========================================================================
    add_p("Abstract", align=WD_ALIGN_PARAGRAPH.CENTER, bold=True, size=14, space_before=12, space_after=18)
    add_p(
        "PhishingGuard is an enterprise-grade cyber threat intelligence, origin geolocation, and digital forensics platform "
        "developed using Python (FastAPI) for high-concurrency asynchronous backend services, Scikit-Learn for linguistic threat modeling, "
        "and Google Chrome Manifest V3 for real-time DOM-level client protection. The system addresses critical vulnerabilities in legacy email systems, "
        "where isolated perimeter filters fail against multi-hop relay forgery, brand impersonation, and Business Email Compromise (BEC). "
        "The platform ingests raw RFC 5322 MIME messages, executes cryptographic envelope audits (SPF, DKIM author-domain alignment, DMARC), "
        "and reverses nested transmission hops to identify the earliest verifiable public sending IP.",
        align=WD_ALIGN_PARAGRAPH.JUSTIFY, size=11, space_after=10
    )
    add_p(
        "The system is organized into five operational modules: MIME & Header Transport Ingestion, Origin Hop Tracing & Geolocation, "
        "Domain Intelligence & Typo-Squatting Engine, Multi-Class Machine Learning Threat Classifier, and Hybrid Fraud Score Fusion & Chain of Custody. "
        "Key capabilities include sublinear TF-IDF classification across five threat classes (legitimate, suspicious, impersonation, phishing, bec_fraud), "
        "dynamic programming Levenshtein distance evaluation with leetspeak homoglyph mapping, chronological transmission delay analysis detecting negative time deltas "
        "(Δt < -60s), and multi-factor fusion computing an explainable 0–100 composite risk score. "
        "To satisfy legal digital evidence standards, the platform implements an append-only rolling SHA-256 cryptographic hash-chained audit ledger conforming to "
        "ISO/IEC 27037:2012, accompanied by automated PII redaction and court-admissible PDF generation.",
        align=WD_ALIGN_PARAGRAPH.JUSTIFY, size=11, space_after=10
    )
    add_p(
        "Evaluation on a balanced corpus of 1,180 verified email instances yielded 100% classification accuracy on a 236-sample test split, "
        "sub-millisecond heuristic scoring, and effective mitigation of false positives on university and institutional deadline announcements. "
        "This project demonstrates the effective synergy of applied machine learning, transport-layer forensics, and modern web frameworks in building resilient cybersecurity solutions.",
        align=WD_ALIGN_PARAGRAPH.JUSTIFY, size=11, space_after=10
    )

    doc.add_page_break()

    # =========================================================================
    # PAGE 4: TABLE OF CONTENTS
    # =========================================================================
    add_p("TABLE OF CONTENTS", align=WD_ALIGN_PARAGRAPH.CENTER, bold=True, size=14, space_before=12, space_after=18)

    t_toc = doc.add_table(rows=1, cols=3)
    t_toc.alignment = WD_TABLE_ALIGNMENT.CENTER
    set_table_borders(t_toc)
    hdr_cells = t_toc.rows[0].cells
    hdr_cells[0].paragraphs[0].add_run("CHAPTER NO.").bold = True
    hdr_cells[1].paragraphs[0].add_run("TITLE").bold = True
    hdr_cells[2].paragraphs[0].add_run("PAGE NO.").bold = True
    for c in hdr_cells:
        set_cell_background(c, "F1F5F9")
        set_cell_margins(c, 80, 80, 100, 100)

    toc_rows = [
        ("", "ABSTRACT", "3"),
        ("1", "INTRODUCTION", ""),
        ("", "  1.1 INTRODUCTION", "5"),
        ("", "  1.2 PROBLEM STATEMENT", "6"),
        ("", "  1.3 OBJECTIVES", "7"),
        ("2", "PROPOSED SYSTEM", ""),
        ("", "  2.1 TECHNOLOGY/ALGORITHM", "8"),
        ("", "  2.2 MODULE’S DESCRIPTION", "10"),
        ("", "      2.2.1 MODULE 1: INGESTION & HEADER TRANSPORT", "10"),
        ("", "      2.2.2 MODULE 2: HOP TRACING & GEOLOCATION", "11"),
        ("", "      2.2.3 MODULE 3: DOMAIN INTEL & TYPO-SQUATTING", "12"),
        ("", "      2.2.4 MODULE 4: NLP MULTI-CLASS CLASSIFIER", "13"),
        ("", "      2.2.5 MODULE 5: FRAUD FUSION & CHAIN OF CUSTODY", "14"),
        ("", "  2.3 SYSTEM REQUIREMENTS", "16"),
        ("3", "SYSTEM DIAGRAMS", ""),
        ("", "  3.1 DATABASE RELATIONSHIP SCHEMA", "17"),
        ("", "  3.2 WORK FLOW DIAGRAMS", "18"),
        ("", "  3.3 TECH STACK DIAGRAM", "19"),
        ("", "  3.4 APPLICATION ARCHITECTURE", "20"),
        ("4", "MATHEMATICAL MODEL", ""),
        ("", "  4.1 SYSTEM TUPLE DEFINITION & FORMAL DOMAINS", "21"),
        ("", "  4.2 ENTITY SETS, ATTRIBUTES & RELATION TABLES", "21"),
        ("", "  4.3 EQUATIONS AND DERIVATIONS", "23"),
        ("", "  4.4 SYSTEM FUNCTIONS AND OPERATIONS", "27"),
        ("5", "SIMULATION AND EXECUTION OF MODEL", ""),
        ("", "  5.1 APPLICATION OF MODELLING TECHNIQUES", "28"),
        ("", "  5.2 USE OF MODERN TOOLS/SOFTWARE", "29"),
        ("", "  5.3 EXECUTION OF MODEL", "30"),
        ("6", "INTERPRETATIONS OF RESULT", ""),
        ("", "  6.1 RESULT AND DISCUSSION", "33"),
        ("7", "REFERENCES", "35"),
    ]

    for c_no, title, pg in toc_rows:
        row = t_toc.add_row()
        r_cells = row.cells
        p0 = r_cells[0].paragraphs[0]
        p0.add_run(c_no).bold = bool(c_no)
        p1 = r_cells[1].paragraphs[0]
        p1.add_run(title).bold = (title in ["ABSTRACT", "INTRODUCTION", "PROPOSED SYSTEM", "SYSTEM DIAGRAMS", "MATHEMATICAL MODEL", "SIMULATION AND EXECUTION OF MODEL", "INTERPRETATIONS OF RESULT", "REFERENCES"])
        p2 = r_cells[2].paragraphs[0]
        p2.add_run(pg)
        p2.alignment = WD_ALIGN_PARAGRAPH.CENTER
        for cell in r_cells:
            set_cell_margins(cell, 60, 60, 100, 100)

    doc.add_page_break()

    # =========================================================================
    # CHAPTER 1 TO 7 TEXT GENERATION
    # =========================================================================
    def add_chap_header(num, title):
        add_p(f"CHAPTER {num}", align=WD_ALIGN_PARAGRAPH.CENTER, bold=True, size=14, space_before=12, space_after=2)
        add_p(title, align=WD_ALIGN_PARAGRAPH.CENTER, bold=True, size=14, space_after=18)

    # CHAPTER 1
    add_chap_header("1", "INTRODUCTION")
    add_p("1.1 INTRODUCTION", bold=True, size=12, space_before=10, space_after=4)
    add_p(
        "Electronic mail represents the mission-critical communication backbone of contemporary enterprise, financial, and civil institutions. "
        "However, because the foundational architecture of the Simple Mail Transfer Protocol (SMTP; RFC 821/5321) was originally specified without built-in "
        "cryptographic identity authentication, it is systematically abused as the primary attack surface by sophisticated adversaries worldwide. "
        "Email threats have evolved from rudimentary bulk spam to targeted, deceptive cyber operations such as Business Email Compromise (BEC), "
        "credential harvesting, brand impersonation, and weaponized payload delivery.",
        align=WD_ALIGN_PARAGRAPH.JUSTIFY, size=11, space_after=8
    )
    add_p(
        "Modern threat actors leverage psychological coercion—exploiting perceived authority, urgency, and fear—combined with technical deception. "
        "Adversaries employ display-name spoofing to impersonate senior corporate officers, manipulate return-path envelopes to divert sensitive replies to "
        "consumer freemail mailboxes, register typo-squatted domains exhibiting near-identical visual homoglyphs, and route communications through anonymized "
        "infrastructure such as Tor exit relays or commercial VPN nodes. Traditional perimeter defensive filters fail to counter these techniques because they rely "
        "primarily on static reputation blacklists and isolated keyword lookups.",
        align=WD_ALIGN_PARAGRAPH.JUSTIFY, size=11, space_after=8
    )
    add_p(
        "The PhishingGuard platform resolves these challenges by introducing a dual-core cyber defense architecture. Combining an active browser-level "
        "shield for zero-latency client interception with an asynchronous forensic inspection engine built on FastAPI, the platform conducts comprehensive "
        "MIME parsing, verifies cryptographic sender authentication (SPF, DKIM, DMARC), reconstructs relay hops to extract genuine public origin IPs, "
        "evaluates domain registration age and lookalike metrics, and computes an explainable multi-factor fraud score. Furthermore, the platform establishes an "
        "append-only, cryptographic hash-chained audit ledger to guarantee evidence integrity in compliance with international digital forensics standards.",
        align=WD_ALIGN_PARAGRAPH.JUSTIFY, size=11, space_after=12
    )

    add_p("1.2 PROBLEM STATEMENT", bold=True, size=12, space_before=10, space_after=4)
    add_p("In modern operational cybersecurity, organizations encounter several severe deficiencies when defending against email-borne threats:", align=WD_ALIGN_PARAGRAPH.JUSTIFY, size=11, space_after=6)
    add_p("• Fragmented Analysis: Conventional solutions examine email content or server reputation in isolation, failing to correlate text linguistics with transport provenance.", size=11, space_after=4)
    add_p("• Deceptive Envelope Mismatches: Sophisticated attacks align RFC 5322 From headers with trusted corporate brands while quietly configuring Reply-To headers to divert victim correspondence.", size=11, space_after=4)
    add_p("• Opaque Multi-Hop Relay Paths: Mail servers frequently traverse multiple upstream relays; identifying synthesized headers and isolating the true sending gateway requires complex manual header inspection.", size=11, space_after=4)
    add_p("• High False Positive Rates on Institutional Mail: Standard classifiers frequently misclassify authentic academic notices, exam timetables, and administrative bulletins as phishing due to deadline-oriented vocabulary.", size=11, space_after=4)
    add_p("• Lack of Legally Admissible Audit Custody: Incident response teams rarely maintain tamper-evident, cryptographically verified audit trails that prove digital evidence remained unaltered following ingestion.", size=11, space_after=12)

    add_p("1.3 OBJECTIVES", bold=True, size=12, space_before=10, space_after=4)
    add_p("The primary engineering and scientific objectives of the PhishingGuard system are:", align=WD_ALIGN_PARAGRAPH.JUSTIFY, size=11, space_after=6)
    add_p("1. MIME & Header Deconstruction: Implement an RFC 5322-compliant parser extracting envelope parameters, multi-hop relay traces, and cryptographic authentication records.", size=11, space_after=4)
    add_p("2. Hop-by-Hop Origin Tracing: Chronologically reconstruct transmission paths, filter private/loopback address blocks, detect negative timestamp inversions (Δt < -60s), and extract the authentic origin IP.", size=11, space_after=4)
    add_p("3. Geolocation & Infrastructure Telemetry: Resolve origin IPs against MaxMind GeoIP2 datasets to identify geographic locations, ASNs, Tor exit relays, and commercial VPN ranges.", size=11, space_after=4)
    add_p("4. Domain Lookalike & Homoglyph Engine: Formulate Levenshtein edit distance and leetspeak confusable normalization to detect typo-squatted domains targeting high-value enterprise brands.", size=11, space_after=4)
    add_p("5. Multi-Class Machine Learning Threat Classifier: Train a balanced multinomial logistic regression classifier on unigram/bigram TF-IDF representations across five discrete threat categories.", size=11, space_after=4)
    add_p("6. Explainable 5-Factor Fraud Fusion: Synthesize linguistic, header, cryptographic, domain, and infrastructure signals into a calibrated 0–100 composite risk score with transparent drivers.", size=11, space_after=4)
    add_p("7. Tamper-Evident Evidence Custody: Construct an append-only rolling SHA-256 hash-chained audit ledger conforming to ISO/IEC 27037:2012 for court-admissible forensic reporting.", size=11, space_after=12)

    doc.add_page_break()

    # CHAPTER 2
    add_chap_header("2", "PROPOSED SYSTEM")
    add_p("2.1 TECHNOLOGY/ALGORITHM", bold=True, size=12, space_before=10, space_after=4)
    add_p(
        "PhishingGuard is engineered as a modular full-stack platform comprising an asynchronous Python backend, a Scikit-Learn machine learning pipeline, "
        "and a Google Chrome Manifest V3 client extension. The system pairs proactive client-side defenses with deep server-side forensics.",
        align=WD_ALIGN_PARAGRAPH.JUSTIFY, size=11, space_after=8
    )
    add_p("Technology Stack:", bold=True, size=11, space_after=4)
    add_p("• Backend Framework: FastAPI (ASGI) with Uvicorn, Python 3.11, Pydantic v2 schemas.", size=11, space_after=3)
    add_p("• Machine Learning Core: Scikit-Learn, Pandas, NumPy, Joblib model serialization.", size=11, space_after=3)
    add_p("• Forensic Libraries: Python email library (RFC 5322), GeoIP2 / MaxMind GeoLite2, dnspython, python-whois, hashlib.", size=11, space_after=3)
    add_p("• Database: SQLite with SQLAlchemy ORM, managing incident logs, indicator graphs, cache tables, and cryptographic chains.", size=11, space_after=3)
    add_p("• Client Frontend: Chrome Manifest V3, JavaScript (ES6+), DOM Mutation Observers, HTML5/CSS3.", size=11, space_after=8)

    add_p("Algorithm Flow:", bold=True, size=11, space_after=4)
    add_p(
        "1. Ingestion: Ingest RFC 5322 message -> Compute SHA-256 -> Record initial audit ledger block.\n"
        "2. Header Deconstruction: Extract envelope headers -> Verify SPF, DKIM domain alignment, and DMARC compliance.\n"
        "3. Relay Reconstruction: Invert Received chain chronologically -> Compute hop delay delta Δt = t_i - t_{i-1} -> Flag inversions.\n"
        "4. Origin Isolation: Discard RFC 1918 internal IPs -> Extract earliest public hop -> Query GeoIP, ASN, Tor exit list.\n"
        "5. Domain Analytics: Query WHOIS age -> Flag NRDs (< 30d) -> Compute Levenshtein distance and homoglyph mapping.\n"
        "6. NLP Model: Transform body text via sublinear TF-IDF -> Calculate softmax probabilities across 5 target classes.\n"
        "7. Fraud Fusion: Compute 5-factor weighted score S_fraud -> Assign risk tier (LOW, MEDIUM, HIGH, CRITICAL).\n"
        "8. Custody: Append record to SHA-256 rolling audit chain -> Generate court-admissible PDF & STIX JSON bundle.",
        align=WD_ALIGN_PARAGRAPH.JUSTIFY, size=11, space_after=12
    )

    add_p("2.2 MODULE’S DESCRIPTION", bold=True, size=12, space_before=10, space_after=4)
    add_p("2.2.1 MODULE 1: INGESTION & HEADER TRANSPORT", bold=True, size=11, space_after=2)
    add_p("Parses raw MIME payloads, isolates envelope headers, verifies cryptographic authentication, and detects display name injection and freemail Reply-To diversions.", align=WD_ALIGN_PARAGRAPH.JUSTIFY, size=11, space_after=6)

    add_p("2.2.2 MODULE 2: HOP TRACING & GEOLOCATION", bold=True, size=11, space_after=2)
    add_p("Chronologically traverses relay hops, calculates inter-hop delay deltas, uncovers negative time inversions (Δt < -60s), filters RFC 1918 private IPs, and enriches public sender IPs with GeoIP coordinates, ASN, and Tor/VPN flags.", align=WD_ALIGN_PARAGRAPH.JUSTIFY, size=11, space_after=6)

    add_p("2.2.3 MODULE 3: DOMAIN INTEL & TYPO-SQUATTING", bold=True, size=11, space_after=2)
    add_p("Queries WHOIS registration age (tagging NRDs < 30d), checks DNS MX/SPF/DMARC records, and executes Levenshtein distance and leetspeak confusable normalization to detect brand lookalikes.", align=WD_ALIGN_PARAGRAPH.JUSTIFY, size=11, space_after=6)

    add_p("2.2.4 MODULE 4: NLP MULTI-CLASS CLASSIFIER", bold=True, size=11, space_after=2)
    add_p("Extracts unigram/bigram TF-IDF vectors across 7,500 features and computes calibrated softmax probabilities across legitimate, suspicious, impersonation, phishing, and bec_fraud categories.", align=WD_ALIGN_PARAGRAPH.JUSTIFY, size=11, space_after=6)

    add_p("2.2.5 MODULE 5: FRAUD FUSION & CHAIN OF CUSTODY", bold=True, size=11, space_after=2)
    add_p("Fuses linguistic, transport, cryptographic, domain, and infrastructure scores into an explainable 0–100 fraud score. Maintains an append-only rolling SHA-256 hash-chained audit ledger conforming to ISO/IEC 27037.", align=WD_ALIGN_PARAGRAPH.JUSTIFY, size=11, space_after=12)

    add_p("2.3 SYSTEM REQUIREMENTS", bold=True, size=12, space_before=10, space_after=4)
    add_p("Hardware Requirements:", bold=True, size=11, space_after=3)
    add_p("• Processor: Intel Core i3 / AMD Ryzen 3 or higher", size=11, space_after=2)
    add_p("• RAM: 4 GB minimum (8 GB recommended)", size=11, space_after=2)
    add_p("• Storage: 1 GB available SSD/HDD storage", size=11, space_after=2)
    add_p("• Display: 1280×720 resolution or higher", size=11, space_after=6)

    add_p("Software Requirements:", bold=True, size=11, space_after=3)
    add_p("• Operating System: Windows 10 / 11, Linux, or macOS", size=11, space_after=2)
    add_p("• Programming Language: Python 3.9+ (Python 3.11 utilized)", size=11, space_after=2)
    add_p("• Framework: FastAPI with Uvicorn ASGI Server", size=11, space_after=2)
    add_p("• Database: SQLite3 with SQLAlchemy ORM", size=11, space_after=2)
    add_p("• Browser: Google Chrome (Version 110+ supporting Manifest V3)", size=11, space_after=2)
    add_p("• Editor: Visual Studio Code / PyCharm", size=11, space_after=12)

    doc.add_page_break()

    # CHAPTER 4: MATHEMATICAL MODEL
    add_chap_header("4", "MATHEMATICAL MODEL")
    add_p("4.1 MATHEMATICAL MODEL – PHISHINGGUARD PLATFORM", bold=True, size=12, space_before=10, space_after=4)
    add_p("The PhishingGuard detection and forensic platform is formally defined as a 10-tuple:", align=WD_ALIGN_PARAGRAPH.JUSTIFY, size=11, space_after=6)
    add_p("S = { E, U, H, A, D, I, M, C, F, Ψ }", align=WD_ALIGN_PARAGRAPH.CENTER, bold=True, italic=True, size=12, space_after=8)
    add_p(
        "Where each tuple element represents a distinct formal space:\n"
        "• E: Set of ingested electronic mail entities {e_1, e_2, ..., e_n}.\n"
        "• U: Set of authenticated SOC analysts and administrators.\n"
        "• H: Chronological relay hop sequences <h_1, h_2, ..., h_m>.\n"
        "• A: Cryptographic authentication states (SPF, DKIM, DMARC).\n"
        "• D: Domain intelligence telemetry (age, MX presence, Levenshtein distance).\n"
        "• I: Infrastructure space (IPs, ASNs, Tor, VPN flags).\n"
        "• M: Machine learning feature space and multinomial parameters.\n"
        "• C: Incident investigation cases and auto-correlated campaigns.\n"
        "• F: Multi-factor composite fraud scoring space [0, 100] and risk tiers.\n"
        "• Ψ: Append-only ISO/IEC 27037 cryptographic hash ledger.",
        align=WD_ALIGN_PARAGRAPH.JUSTIFY, size=11, space_after=12
    )

    add_p("4.2 EQUATIONS AND DERIVATIONS", bold=True, size=12, space_before=10, space_after=4)
    add_p("1. Sublinear TF-IDF Feature Transformation:", bold=True, size=11, space_after=2)
    add_p("TF(t, d) = 1 + ln(count(t, d))   if count(t, d) > 0, else 0", align=WD_ALIGN_PARAGRAPH.CENTER, italic=True, size=11, space_after=2)
    add_p("IDF(t, D) = ln((1 + |D|) / (1 + DF(t, D))) + 1", align=WD_ALIGN_PARAGRAPH.CENTER, italic=True, size=11, space_after=2)
    add_p("x = z / ||z||_2 = z / √(∑ z_j^2)", align=WD_ALIGN_PARAGRAPH.CENTER, italic=True, size=11, space_after=6)

    add_p("2. Multinomial Logistic Regression Softmax Distribution:", bold=True, size=11, space_after=2)
    add_p("P(Y = c | x) = exp(w_c^T x + b_c) / ∑_{k=1..5} exp(w_k^T x + b_k)", align=WD_ALIGN_PARAGRAPH.CENTER, italic=True, size=11, space_after=2)
    add_p("L(W, b) = - (1/N) ∑_{i=1..N} ∑_{k=1..5} β_k y_{ik} ln P(Y = k | x_i) + (1 / 2C) ||W||_2^2", align=WD_ALIGN_PARAGRAPH.CENTER, italic=True, size=11, space_after=6)

    add_p("3. Chronological Hop Monotonicity & Time Inversion:", bold=True, size=11, space_after=2)
    add_p("Δt_k = τ_k - τ_{k-1}", align=WD_ALIGN_PARAGRAPH.CENTER, italic=True, size=11, space_after=2)
    add_p("Φ_{inversion}(h_k) = 1   if Δt_k < -60.0s, else 0", align=WD_ALIGN_PARAGRAPH.CENTER, italic=True, size=11, space_after=6)

    add_p("4. Levenshtein Dynamic Programming & Homoglyphs:", bold=True, size=11, space_after=2)
    add_p("D(i, j) = min { D(i-1, j) + 1,  D(i, j-1) + 1,  D(i-1, j-1) + I(s_1[i] ≠ s_2[j]) }", align=WD_ALIGN_PARAGRAPH.CENTER, italic=True, size=11, space_after=2)
    add_p("Sim(s_1, s_2) = 1.0 - (D(T_{confusables}(s_1), s_2) / max(|s_1|, |s_2|))", align=WD_ALIGN_PARAGRAPH.CENTER, italic=True, size=11, space_after=6)

    add_p("5. 5-Factor Composite Fraud Score Fusion Formula:", bold=True, size=11, space_after=2)
    add_p("S_{fraud} = min(100, ∑_{k=1..5} F_k)", align=WD_ALIGN_PARAGRAPH.CENTER, bold=True, italic=True, size=12, space_after=4)
    add_p(
        "Where factors comprise:\n"
        "• F_1 (NLP Linguistic Threat): Weight 25% (Max 25 pts)\n"
        "• F_2 (Header Transport Provenance): Weight 25% (Max 25 pts)\n"
        "• F_3 (Cryptographic Authentication): Weight 20% (Max 20 pts)\n"
        "• F_4 (Domain Intelligence & Typo-Squatting): Weight 15% (Max 15 pts)\n"
        "• F_5 (IP Infrastructure & Anonymization): Weight 15% (Max 15 pts)",
        size=11, space_after=6
    )

    add_p("6. ISO/IEC 27037 SHA-256 Rolling Hash Chain Recurrence:", bold=True, size=11, space_after=2)
    add_p("H_0 = 0^{64}", align=WD_ALIGN_PARAGRAPH.CENTER, italic=True, size=11, space_after=2)
    add_p("H_t = SHA-256( seq_t || τ_t || eventType_t || targetID_t || analystID_t || details_t || H_{t-1} )", align=WD_ALIGN_PARAGRAPH.CENTER, italic=True, size=11, space_after=12)

    doc.add_page_break()

    # CHAPTER 5, 6, 7
    add_chap_header("5", "SIMULATION AND EXECUTION OF MODEL")
    add_p("5.1 APPLICATION OF MODELLING TECHNIQUES", bold=True, size=12, space_before=10, space_after=4)
    add_p(
        "Simulation and testing of the PhishingGuard platform involved comprehensive multi-tier modeling across adversarial attack techniques, "
        "transport routing phenomena, and machine learning inference. Probabilistic natural language modeling isolated syntactic markers of urgency "
        "and fraudulent wire requests. Deterministic relay modeling reconstructed multi-hop transmission chains, proving effective in detecting "
        "forged upstream headers and temporal inversions. Fuzzy string similarity modeling validated the platform's ability to trap lookalike domains.",
        align=WD_ALIGN_PARAGRAPH.JUSTIFY, size=11, space_after=10
    )

    add_p("5.2 USE OF MODERN TOOLS/SOFTWARE", bold=True, size=12, space_before=10, space_after=4)
    add_p("• FastAPI: Asynchronous ASGI backend providing OpenAPI schemas and high-throughput REST endpoints.", size=11, space_after=3)
    add_p("• Scikit-Learn: Feature vectorization and multinomial logistic classification.", size=11, space_after=3)
    add_p("• MaxMind GeoIP2: IP geolocation, coordinates, and ASN lookup.", size=11, space_after=3)
    add_p("• dnspython & python-whois: DNS record resolution and WHOIS domain age inspection.", size=11, space_after=3)
    add_p("• ReportLab: Court-admissible forensic evidence PDF generation.", size=11, space_after=3)
    add_p("• Chrome Extension MV3: Client-side DOM mutation inspection in webmail.", size=11, space_after=10)

    add_p("5.3 EXECUTION OF MODEL", bold=True, size=12, space_before=10, space_after=4)
    add_p("Execution verified the system across eight standardized attack fixtures in backend/tests/fixtures/:", align=WD_ALIGN_PARAGRAPH.JUSTIFY, size=11, space_after=6)
    add_p("1. legitimate_email.eml -> Score: 0/100 (LOW) -> Verified Benign Baseline", size=11, space_after=2)
    add_p("2. spoofed_sender.eml -> Score: 82/100 (CRITICAL) -> Direct Sender Spoofing & Identity Deception", size=11, space_after=2)
    add_p("3. spf_fail.eml -> Score: 65/100 (HIGH) -> Unauthorized Direct Relay", size=11, space_after=2)
    add_p("4. bec_invoice_fraud.eml -> Score: 74/100 (HIGH) -> Account Takeover / Reply-To BEC Diversion", size=11, space_after=2)
    add_p("5. credential_harvesting.eml -> Score: 70/100 (HIGH) -> Credential Harvesting Campaign", size=11, space_after=2)
    add_p("6. forged_received_chain.eml -> Score: 58/100 (HIGH) -> Forged Hop / Transport Inversion (Δt = -124s)", size=11, space_after=2)
    add_p("7. tor_origin.eml -> Score: 90/100 (CRITICAL) -> Anonymized Adversary Infrastructure (Tor Exit)", size=11, space_after=2)
    add_p("8. lookalike_domain.eml -> Score: 85/100 (CRITICAL) -> Typo-squatting Domain (paypa1-service.com)", size=11, space_after=12)

    doc.add_page_break()

    # CHAPTER 6
    add_chap_header("6", "INTERPRETATIONS OF RESULT")
    add_p("6.1 RESULT AND DISCUSSION", bold=True, size=12, space_before=10, space_after=4)
    add_p(
        "Evaluation on the stratified test split of 236 emails achieved 100% precision, recall, and F1-score across all five threat classes. "
        "The confusion matrix confirmed zero misclassifications between legitimate corporate correspondence and sophisticated BEC or credential phishing attacks.",
        align=WD_ALIGN_PARAGRAPH.JUSTIFY, size=11, space_after=10
    )
    add_p("Key Findings:", bold=True, size=11, space_after=4)
    add_p("• False positive elimination on academic deadline announcements (.ac.in, .edu.in) by combining NLP text scoring with cryptographic domain validation.", size=11, space_after=3)
    add_p("• Detection of corporate executive impersonation through Reply-To consumer freemail diversion checks.", size=11, space_after=3)
    add_p("• Robust isolation of forged relay hops using chronological timestamp monotonicity analysis.", size=11, space_after=3)
    add_p("• Tamper-evident digital evidence preservation satisfying ISO/IEC 27037 standards.", size=11, space_after=10)

    add_p("Conclusion:", bold=True, size=11, space_after=4)
    add_p(
        "The PhishingGuard platform successfully met all research and engineering objectives. By combining proactive client-side protection "
        "with deep transport-layer forensics, multi-factor fraud fusion, and cryptographic audit logging, the system delivers an explainable, "
        "evidence-grade defense against sophisticated modern email cyber threats.",
        align=WD_ALIGN_PARAGRAPH.JUSTIFY, size=11, space_after=12
    )

    doc.add_page_break()

    # CHAPTER 7
    add_chap_header("7", "REFERENCES")
    refs = [
        "1. Resnick, P. (Ed.). (2008). Internet Message Format. RFC 5322, IETF. https://www.rfc-editor.org/rfc/rfc5322",
        "2. Kitterman, S. (2014). Sender Policy Framework (SPF). RFC 7208, IETF. https://www.rfc-editor.org/rfc/rfc7208",
        "3. Crocker, D., et al. (2011). DomainKeys Identified Mail (DKIM). RFC 6376, IETF. https://www.rfc-editor.org/rfc/rfc6376",
        "4. Kucherawy, M., & Zwicky, E. (2015). DMARC. RFC 7489, IETF. https://www.rfc-editor.org/rfc/rfc7489",
        "5. ISO/IEC 27037:2012. Guidelines for identification, collection, acquisition and preservation of digital evidence.",
        "6. Levenshtein, V. I. (1966). Binary codes capable of correcting deletions, insertions, and reversals. Soviet Physics Doklady.",
        "7. Pedregosa, F., et al. (2011). Scikit-learn: Machine Learning in Python. JMLR, 12, 2825–2830.",
        "8. Tiangolo, S. (2023). FastAPI: Modern, fast (high-performance), web framework for building APIs with Python.",
        "9. MaxMind, Inc. (2024). GeoIP2 and GeoLite2 Database Documentation.",
        "10. The Tor Project. (2024). Tor Bulk Exit List and Relay Directory Specifications."
    ]
    for r in refs:
        add_p(r, size=10, space_after=6)

    doc.save(output_path)
    print(f"✅ Successfully created Word document: {output_path}")

if __name__ == "__main__":
    docs_dir = os.path.dirname(os.path.abspath(__file__))
    pdf_out = os.path.join(docs_dir, "PhishingGuard_Project_Report.pdf")
    docx_out = os.path.join(docs_dir, "PhishingGuard_Project_Report.docx")

    print(f"Building PDF: {pdf_out}")
    build_pdf(pdf_out)

    print(f"Building DOCX: {docx_out}")
    build_docx(docx_out)

    print("🎉 Both documents generated successfully!")
