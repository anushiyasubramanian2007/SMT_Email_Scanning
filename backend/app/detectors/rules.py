from typing import List
import re
from app.schemas.schemas import (
    EmailAnalysisRequest, EmailAnalysisResponse, Indicator, 
    UrlAnalysisRequest, UrlAnalysisResponse, AttachmentResult
)

# Lists of file extension classifications
DANGEROUS_EXTENSIONS = {
    '.exe', '.scr', '.bat', '.cmd', '.vbs', '.js', '.wsf', '.hta', 
    '.cpl', '.msi', '.jar', '.vhd', '.dll', '.com', '.pif', '.reg', 
    '.ps1', '.apk', '.lnk', '.gadget', '.msp', '.cab', '.inf', 
    '.application', '.appref-ms', '.vbe', '.jse'
}

MACRO_EXTENSIONS = {'.docm', '.xlsm', '.pptm', '.dotm', '.xltm', '.potm'}
ARCHIVE_EXTENSIONS = {'.zip', '.rar', '.7z', '.tar', '.gz', '.ace', '.arj', '.z', '.bz2'}
DISK_IMAGE_EXTENSIONS = {'.iso', '.img', '.vhd', '.vhdx'}
SAFE_DOCUMENT_EXTENSIONS = {
    '.pdf', '.docx', '.xlsx', '.pptx', '.txt', '.csv', '.rtf', 
    '.png', '.jpg', '.jpeg', '.gif', '.svg', '.mp3', '.mp4'
}

def analyze_email_rules(request: EmailAnalysisRequest) -> EmailAnalysisResponse:
    indicators: List[Indicator] = []
    attachments_analyzed: List[AttachmentResult] = []
    score = 0
    
    text_to_analyze = (request.subject + " " + request.body).lower()

    # Rule 1: Urgent or threatening language
    urgent_keywords = [
        "urgent", "immediate action required", "suspended", "verify your account", 
        "password reset", "update your payment", "account will be closed", 
        "unauthorized login", "action required", "billing issue", "wire transfer immediately",
        "account locked", "security alert", "delinquent", "arrest warrant"
    ]
    for keyword in urgent_keywords:
        if keyword in text_to_analyze:
            indicators.append(Indicator(type="URGENCY", description=f"Found urgent language: '{keyword}'"))
            score += 2
            
    # Rule 2: Suspicious sender (Brand Impersonation)
    targeted_brands = [
        "paypal", "microsoft", "google", "amazon", "apple", 
        "bank of america", "netflix", "facebook", "meta", "chase", "wells fargo", "dhl", "fedex", "walmart"
    ]
    sender_name_lower = request.sender_name.lower()
    sender_email_lower = request.sender_email.lower()

    for brand in targeted_brands:
        if re.search(r'\b' + re.escape(brand) + r'\b', sender_name_lower):
            domain_part = sender_email_lower.split('@')[-1] if '@' in sender_email_lower else ""
            if brand not in domain_part:
                indicators.append(Indicator(
                    type="IMPERSONATION", 
                    description=f"Sender display name claims '{brand.capitalize()}', but email domain is '{domain_part}'."
                ))
                score += 5
                break
        
    # Rule 2.1: Anomalous Sender Email
    domain_part = request.sender_email.split('@')[-1] if '@' in request.sender_email else ""
    if len(re.findall(r'\d', domain_part)) >= 4:
        indicators.append(Indicator(
            type="ANOMALOUS_DOMAIN", 
            description=f"Sender domain ({domain_part}) contains an unusually high number of digits."
        ))
        score += 3
        
    # Rule 3: Excessively high link count
    if len(request.links) > 20:
        indicators.append(Indicator(
            type="EXCESSIVE_LINKS", 
            description=f"Email contains {len(request.links)} links, which is unusually high."
        ))
        score += 1

    # Rule 4: Authentication Check (SPF/DKIM/DMARC)
    if hasattr(request, 'is_authenticated') and request.is_authenticated is False:
        indicators.append(Indicator(
            type="UNAUTHENTICATED", 
            description="Email failed standard domain security checks (SPF/DKIM/DMARC)."
        ))
        score += 2

    # Rule 5: URL Analysis Integration
    if hasattr(request, 'links') and request.links:
        for url in request.links:
            url_lower = url.lower()
            if url_lower.startswith("http://") and not url_lower.startswith("http://localhost"):
                indicators.append(Indicator(type="UNENCRYPTED_LINK", description=f"Email contains unencrypted link: {url[:60]}..."))
                score += 1
            if re.search(r'https?://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', url_lower):
                indicators.append(Indicator(type="IP_BASED_URL", description=f"Email contains an IP-address link instead of a registered domain: {url[:60]}..."))
                score += 5
            bad_domains = ["test-phish.com", "evil-site.net", "fake-login.com", "apple-id-verify.co", "netflx-update.cc", "sec-auth-check.org"]
            for bad_domain in bad_domains:
                if bad_domain in url_lower:
                    indicators.append(Indicator(type="KNOWN_MALICIOUS_LINK", description=f"Email contains known malicious URL: {bad_domain}"))
                    score += 6

    # Rule 6: Deep Attachment Analysis
    has_dangerous_attachment = False
    if hasattr(request, 'attachments') and request.attachments:
        for attachment in request.attachments:
            att_clean = attachment.strip()
            if not att_clean:
                continue
            att_lower = att_clean.lower()
            
            att_status = "safe"
            att_threat = "None"
            att_details = "Verified safe document format."
            
            # Check 6.1: Right-to-Left Override (RTLO) Unicode trick (\u202e)
            if '\u202e' in att_clean:
                indicators.append(Indicator(
                    type="RTLO_ATTACHMENT",
                    description=f"🚨 Critical: Attachment '{att_clean}' uses Right-to-Left Override Unicode spoofing to disguise its real extension!"
                ))
                score += 10
                has_dangerous_attachment = True
                att_status = "phishing"
                att_threat = "RTLO Extension Spoofing"
                att_details = "Hidden Unicode reversal disguised the real file extension."
            
            # Check 6.2: Space-padding extension hiding (e.g. "invoice     .exe")
            elif re.search(r'\s{3,}\.[a-zA-Z0-9]+$', att_clean):
                indicators.append(Indicator(
                    type="SPACE_PADDING_ATTACHMENT",
                    description=f"🚨 Attachment '{att_clean}' contains excessive spacing to hide its true executable extension."
                ))
                score += 10
                has_dangerous_attachment = True
                att_status = "phishing"
                att_threat = "Hidden Executable Extension"
                att_details = "Padded spaces used to hide file extension from view."

            # Check 6.3: Double Extension Camouflage (e.g. invoice.pdf.exe)
            elif att_lower.count('.') > 1:
                parts = att_lower.split('.')
                final_ext = '.' + parts[-1]
                preceding_exts = parts[1:-1]
                
                if final_ext in DANGEROUS_EXTENSIONS:
                    indicators.append(Indicator(
                        type="DOUBLE_EXTENSION_ATTACHMENT",
                        description=f"🚨 Critical: Double-extension camouflage detected: '{att_clean}'. Disguised as a document to trick users into running executable code."
                    ))
                    score += 10
                    has_dangerous_attachment = True
                    att_status = "phishing"
                    att_threat = "Double-Extension Malware"
                    att_details = f"File masquerades as a .{preceding_exts[-1]} document while executing as a {final_ext} program."
                elif final_ext in MACRO_EXTENSIONS:
                    indicators.append(Indicator(
                        type="MACRO_ATTACHMENT",
                        description=f"⚠️ Macro-enabled Office attachment detected: '{att_clean}'."
                    ))
                    score += 4
                    att_status = "suspicious"
                    att_threat = "Macro Document"
                    att_details = "Macro code in this file can download external malware payloads."
                elif final_ext in ARCHIVE_EXTENSIONS or final_ext in DISK_IMAGE_EXTENSIONS:
                    indicators.append(Indicator(
                        type="ARCHIVE_CONTAINER_ATTACHMENT",
                        description=f"⚠️ Compressed container attachment: '{att_clean}'. Attackers frequently pack malware inside archives."
                    ))
                    score += 3
                    att_status = "suspicious"
                    att_threat = "Archive Container"
                    att_details = "Compressed archive format often used to bypass email inspection."
                else:
                    # Regular multiple dot, check if final extension is dangerous
                    if any(att_lower.endswith(ext) for ext in DANGEROUS_EXTENSIONS):
                        indicators.append(Indicator(
                            type="DANGEROUS_ATTACHMENT",
                            description=f"🚨 Dangerous executable attachment detected: '{att_clean}'."
                        ))
                        score += 10
                        has_dangerous_attachment = True
                        att_status = "phishing"
                        att_threat = "Executable Program"
                        att_details = "Dangerous executable file format."
                    else:
                        att_status = "safe"
                        att_threat = "None"
                        att_details = f"Standard document file format ({parts[-1].upper()})."

            # Check 6.4: Direct dangerous executable extension
            elif any(att_lower.endswith(ext) for ext in DANGEROUS_EXTENSIONS):
                ext_matched = next(ext for ext in DANGEROUS_EXTENSIONS if att_lower.endswith(ext))
                indicators.append(Indicator(
                    type="DANGEROUS_ATTACHMENT",
                    description=f"🚨 Dangerous executable attachment detected: '{att_clean}' ({ext_matched}). Executable files can run malware directly on your computer."
                ))
                score += 10
                has_dangerous_attachment = True
                att_status = "phishing"
                att_threat = "Malicious Executable"
                att_details = f"Executable {ext_matched} file format can compromise your system."

            # Check 6.5: Macro-enabled Office document
            elif any(att_lower.endswith(ext) for ext in MACRO_EXTENSIONS):
                indicators.append(Indicator(
                    type="MACRO_ATTACHMENT",
                    description=f"⚠️ Macro-enabled document detected: '{att_clean}'. Contains automated scripts that can download malicious payloads."
                ))
                score += 4
                att_status = "suspicious"
                att_threat = "Macro Document"
                att_details = "Contains VBA macros that can execute commands."

            # Check 6.6: Disk images or archives
            elif any(att_lower.endswith(ext) for ext in DISK_IMAGE_EXTENSIONS):
                indicators.append(Indicator(
                    type="DISK_IMAGE_ATTACHMENT",
                    description=f"⚠️ Disk image attachment: '{att_clean}'. Disk images (.iso/.img) bypass Mark-of-the-Web (MOTW) security checks."
                ))
                score += 4
                att_status = "suspicious"
                att_threat = "Disk Image"
                att_details = "Disk image container format commonly used in phishing attacks."
                
            elif any(att_lower.endswith(ext) for ext in ARCHIVE_EXTENSIONS):
                # Check for suspicious invoice/payment archive lures
                lure_words = ["invoice", "receipt", "payment", "statement", "remittance", "wire", "order", "document", "swift"]
                if any(w in att_lower for w in lure_words) or any(w in text_to_analyze for w in lure_words):
                    indicators.append(Indicator(
                        type="SUSPICIOUS_ARCHIVE",
                        description=f"⚠️ Suspicious archive attachment: '{att_clean}'. Archives claiming to be financial documents often contain hidden malware."
                    ))
                    score += 4
                    att_status = "suspicious"
                    att_threat = "Suspicious Financial Archive"
                    att_details = "Compressed archive purporting to be a financial receipt or invoice."
                else:
                    att_status = "safe"
                    att_threat = "None"
                    att_details = "Standard compressed archive."

            # Check 6.7: Safe standard documents
            elif any(att_lower.endswith(ext) for ext in SAFE_DOCUMENT_EXTENSIONS):
                indicators.append(Indicator(
                    type="ATTACHMENT_INSPECTED",
                    description=f"📎 Attachment inspected: '{att_clean}' (Standard safe document format). No malicious characteristics detected."
                ))
                att_status = "safe"
                att_threat = "None"
                att_details = "Standard safe document format. Passed static heuristic checks."
            else:
                att_status = "safe"
                att_threat = "None"
                att_details = "Attachment inspected. No dangerous executable indicators found."

            attachments_analyzed.append(AttachmentResult(
                filename=att_clean,
                status=att_status,
                threat_type=att_threat,
                details=att_details
            ))

    # Check 7: Text vs Attachment Lure Correlation
    if has_dangerous_attachment and any(w in text_to_analyze for w in ["invoice", "receipt", "payment", "document", "report", "review"]):
        indicators.append(Indicator(
            type="LURE_MISMATCH",
            description="🚨 Phishing Lure Mismatch: Email text claims to provide a document or invoice, but the attachment is an executable program!"
        ))
        score += 3

    # Determine verdict based on score and attachments
    if score >= 5 or has_dangerous_attachment:
        verdict = "phishing"
        display_verdict = "PHISHING"
        risk_category = "High Risk"
        if has_dangerous_attachment:
            explanation = "Phishing threat detected: Malicious or dangerous executable attachment identified in this email."
        else:
            explanation = "Multiple high-risk indicators or malicious patterns were detected in this email."
        recommended_action = "Do NOT open attachments or click links. Report or delete this email immediately."
    elif score >= 2:
        verdict = "suspicious"
        display_verdict = "SUSPICIOUS"
        risk_category = "Medium Risk"
        explanation = "Suspicious patterns or attachment characteristics detected. Proceed with caution."
        recommended_action = "Verify the sender authenticity and inspect attachment origins before taking any action."
    else:
        verdict = "legitimate"
        display_verdict = "LEGITIMATE"
        risk_category = "Low Risk"
        explanation = "Verified Legitimate: No phishing language, sender spoofing, malicious links, or dangerous attachments detected."
        recommended_action = "This email is legitimate. Safe to interact with."

    return EmailAnalysisResponse(
        verdict=verdict,
        display_verdict=display_verdict,
        risk_category=risk_category,
        indicators=indicators,
        attachments_analyzed=attachments_analyzed,
        explanation=explanation,
        recommended_action=recommended_action
    )

def analyze_url(request: UrlAnalysisRequest) -> UrlAnalysisResponse:
    from app.services.virustotal import check_url_virustotal
    
    url = request.url.lower()
    indicators = []
    score = 0
    
    # --- 1. THREAT INTELLIGENCE (VirusTotal) ---
    vt_results = check_url_virustotal(url)
    if vt_results:
        malicious = vt_results["malicious"]
        if malicious > 0:
            indicators.append(Indicator(
                type="VIRUSTOTAL_MALICIOUS", 
                description=f"VirusTotal Alert: {malicious} security vendors flagged this URL as malicious."
            ))
            score += 10
            
    # --- 2. RULE-BASED CHECKS ---
    if url.startswith("http://"):
        indicators.append(Indicator(type="UNENCRYPTED", description="URL uses unencrypted HTTP."))
        score += 1
        
    if re.search(r'https?://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', url):
        indicators.append(Indicator(type="IP_BASED_URL", description="URL uses an IP address instead of a domain name."))
        score += 3
        
    bad_domains = ["test-phish.com", "evil-site.net", "fake-login.com", "apple-id-verify.co", "netflx-update.cc", "sec-auth-check.org"]
    for domain in bad_domains:
        if domain in url:
            indicators.append(Indicator(type="KNOWN_MALICIOUS", description=f"URL matches a known bad domain: {domain}"))
            score += 5
            
    bad_keywords = ["login", "verify", "update-account", "secure-auth", "signin", "banking", "confirm", "billing", "recovery"]
    for keyword in bad_keywords:
        if keyword in url:
            indicators.append(Indicator(type="SUSPICIOUS_KEYWORD", description=f"URL contains suspicious keyword: {keyword}"))
            score += 1

    if score >= 5:
        verdict = "phishing"
    elif score >= 2:
        verdict = "suspicious"
    else:
        verdict = "safe"
        
    return UrlAnalysisResponse(verdict=verdict, indicators=indicators)
