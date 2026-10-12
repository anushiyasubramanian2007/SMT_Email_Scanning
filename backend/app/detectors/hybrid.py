from app.schemas.schemas import EmailAnalysisRequest, EmailAnalysisResponse, Indicator
from app.detectors.rules import analyze_email_rules
from app.ml.model import predict_phishing

def analyze_email_hybrid(request: EmailAnalysisRequest) -> EmailAnalysisResponse:
    # 1. Run rule-based and attachment analysis
    rule_response = analyze_email_rules(request)
    
    # 2. Run ML analysis on email text (Subject + Body)
    text_to_analyze = (request.subject + " " + request.body).strip()
    ml_result = predict_phishing(text_to_analyze) if text_to_analyze else {"is_phishing": False, "confidence": 0.1, "error": None}
    
    # Check if high-risk rule indicators exist (e.g. dangerous attachments, impersonation, bad links)
    high_risk_indicator_types = {
        "VIRUSTOTAL_MALICIOUS", "DANGEROUS_ATTACHMENT", "DOUBLE_EXTENSION_ATTACHMENT", 
        "RTLO_ATTACHMENT", "SPACE_PADDING_ATTACHMENT", "LURE_MISMATCH",
        "IMPERSONATION", "IP_BASED_URL", "KNOWN_MALICIOUS_LINK"
    }
    has_high_risk_rule = any(ind.type in high_risk_indicator_types for ind in rule_response.indicators)

    # If ML model failed to load, return rule-based result with fallback
    if ml_result.get("error"):
        rule_response.indicators.append(
            Indicator(type="ML_ERROR", description=f"AI Model notice: {ml_result['error']}. Heuristic rules utilized.")
        )
        return rule_response
        
    # 3. Combine results
    is_phishing_ml = ml_result["is_phishing"]
    confidence = ml_result["confidence"]
    
    # Case A: If high-risk attachment, malicious URL, or impersonation exists -> Instant PHISHING
    if has_high_risk_rule or rule_response.verdict == "phishing":
        rule_response.verdict = "phishing"
        rule_response.display_verdict = "PHISHING"
        rule_response.risk_category = "High Risk"
        if is_phishing_ml:
            rule_response.indicators.append(
                Indicator(type="AI_DETECTION", description=f"AI NLP Engine confirmed phishing language patterns ({confidence*100:.1f}% confidence).")
            )
        else:
            rule_response.indicators.append(
                Indicator(type="AI_INFO", description=f"AI Text score is benign ({(1 - confidence)*100:.1f}% safe), but critical attachment or heuristic threats override verdict.")
            )
        rule_response.explanation = "Critical threat detected: Malicious attachment, dangerous URL, or spoofing pattern found."
        rule_response.recommended_action = "Do NOT open attachments or click links. Report or delete this email immediately."
        return rule_response

    # Case B: AI Model detects phishing with very high confidence (>= 0.80) -> PHISHING
    if is_phishing_ml and confidence >= 0.80:
        rule_response.indicators.append(
            Indicator(type="AI_DETECTION", description=f"AI NLP Engine detected strong phishing language patterns ({confidence*100:.1f}% confidence).")
        )
        rule_response.verdict = "phishing"
        rule_response.display_verdict = "PHISHING"
        rule_response.risk_category = "High Risk"
        rule_response.explanation = "AI NLP engine detected strong deceptive or credential-theft phishing patterns in email text."
        rule_response.recommended_action = "Do not click links or download attachments. Verify sender authenticity."
        return rule_response

    # Check for recognized institutional or academic domain (e.g. .ac.in, .edu.in, .gov.in, .edu)
    sender_domain = request.sender_email.split('@')[-1].lower() if '@' in request.sender_email else ""
    is_trusted_institutional_domain = any(
        sender_domain.endswith(tld) for tld in [
            ".ac.in", ".edu.in", ".gov.in", ".nic.in", ".res.in",
            ".edu", ".gov", ".mil"
        ]
    )

    # Case C.1: Institutional domain with mild deadline/marketing language and no high-risk threats -> LEGITIMATE
    if is_trusted_institutional_domain and not has_high_risk_rule and rule_response.verdict != "phishing":
        if is_phishing_ml:
            rule_response.indicators.append(
                Indicator(
                    type="INSTITUTIONAL_ANNOUNCEMENT", 
                    description=f"Institutional announcement or deadline language detected from verified domain '{sender_domain}'. No deceptive links, spoofing, or malware found."
                )
            )
        rule_response.verdict = "legitimate"
        rule_response.display_verdict = "LEGITIMATE"
        rule_response.risk_category = "Low Risk"
        rule_response.explanation = f"Legitimate institutional communication from {sender_domain}. Standard academic/organizational announcement."
        rule_response.recommended_action = "This email is legitimate. Safe to interact with."
        return rule_response

    # Case C.2: Mild urgency, moderate AI score, or macro attachment -> SUSPICIOUS (Medium Risk)
    if (is_phishing_ml and confidence >= 0.50) or rule_response.verdict == "suspicious":
        if is_phishing_ml and confidence >= 0.50:
            rule_response.indicators.append(
                Indicator(type="AI_SUSPICIOUS", description=f"AI NLP Engine flagged mild urgency or marketing language ({confidence*100:.1f}% score).")
            )
        rule_response.verdict = "suspicious"
        rule_response.display_verdict = "SUSPICIOUS"
        rule_response.risk_category = "Medium Risk"
        rule_response.explanation = "Suspicious patterns or urgency keywords detected. No critical malware or brand spoofing found."
        rule_response.recommended_action = "Verify the sender and inspect attachments carefully before taking action."
        return rule_response

    # Case D: All clean -> LEGITIMATE (Safe - Low Risk)
    rule_response.indicators.append(
        Indicator(type="AI_SAFE", description=f"AI NLP Model analyzed email text and confirmed legitimate communication ({(1 - confidence)*100:.1f}% safe confidence).")
    )
    rule_response.verdict = "legitimate"
    rule_response.display_verdict = "LEGITIMATE"
    rule_response.risk_category = "Low Risk"
    rule_response.explanation = "Verified Legitimate: No phishing language, sender spoofing, malicious links, or dangerous attachments detected."
    rule_response.recommended_action = "This email is legitimate. Safe to interact with."
        
    return rule_response
