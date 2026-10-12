import sys
import os

if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

# Ensure backend directory is in path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.schemas.schemas import EmailAnalysisRequest
from app.detectors.hybrid import analyze_email_hybrid

def run_tests():
    print("=" * 60)
    print("RUNNING COMPREHENSIVE PHISHINGGUARD VERDICT & ATTACHMENT TESTS")
    print("=" * 60)

    # Test 1: Legitimate Email with Safe Attachment
    print("\n--- Test 1: Legitimate Email + Safe Attachments ---")
    req1 = EmailAnalysisRequest(
        sender_name="Placement Cell",
        sender_email="placement@university.edu",
        subject="Schedule for campus recruitment drives and semester exams",
        body="Dear Students, please find the end semester examination timetable attached for your reference. All regular classes will resume as per schedule.",
        links=["https://university.edu/student-portal"],
        attachments=["semester_timetable.pdf", "guidelines.docx"],
        is_authenticated=True
    )
    res1 = analyze_email_hybrid(req1)
    print(f"Verdict: {res1.verdict} (Display: {res1.display_verdict})")
    print(f"Risk Category: {res1.risk_category}")
    print(f"Explanation: {res1.explanation}")
    print(f"Attachments Analyzed: {len(res1.attachments_analyzed)}")
    for att in res1.attachments_analyzed:
        print(f"  [ATT] {att.filename} -> Status: {att.status}, Details: {att.details}")
    assert res1.verdict in ["legitimate", "safe"], f"Expected legitimate, got {res1.verdict}"
    print("[PASS] TEST 1 PASSED: Correctly identified as LEGITIMATE")

    # Test 2: Phishing Text (Urgent Account Lock + Brand Impersonation)
    print("\n--- Test 2: Phishing Urgent Text (Brand Spoofing) ---")
    req2 = EmailAnalysisRequest(
        sender_name="PayPal Security Team",
        sender_email="alert@paypal-update-security.com",
        subject="URGENT: Your account has been suspended! Immediate action required",
        body="Immediate action required: Unauthorized activity was detected on your bank account. Secure it now or your account will be closed.",
        links=["http://192.168.1.100/login", "http://test-phish.com"],
        attachments=[],
        is_authenticated=True
    )
    res2 = analyze_email_hybrid(req2)
    print(f"Verdict: {res2.verdict} (Display: {res2.display_verdict})")
    print(f"Risk Category: {res2.risk_category}")
    print(f"Explanation: {res2.explanation}")
    print(f"Indicators Count: {len(res2.indicators)}")
    for ind in res2.indicators:
        print(f"  [IND] [{ind.type}] {ind.description}")
    assert res2.verdict == "phishing", f"Expected phishing, got {res2.verdict}"
    print("[PASS] TEST 2 PASSED: Correctly identified as PHISHING")

    # Test 3: Normal Text + Malicious Executable Attachment (.exe masquerade)
    print("\n--- Test 3: Normal Text + Dangerous Double-Extension (.pdf.exe) ---")
    req3 = EmailAnalysisRequest(
        sender_name="Alice Smith",
        sender_email="alice@partner-firm.com",
        subject="Please find the attached invoice for this month",
        body="Hi team, hope you are doing well. Please review the attached invoice document.",
        links=[],
        attachments=["invoice_september.pdf.exe"],
        is_authenticated=True
    )
    res3 = analyze_email_hybrid(req3)
    print(f"Verdict: {res3.verdict} (Display: {res3.display_verdict})")
    print(f"Risk Category: {res3.risk_category}")
    print(f"Explanation: {res3.explanation}")
    for att in res3.attachments_analyzed:
        print(f"  [ATT] {att.filename} -> Status: {att.status}, Threat: {att.threat_type}, Details: {att.details}")
    for ind in res3.indicators:
        print(f"  [IND] [{ind.type}] {ind.description}")
    assert res3.verdict == "phishing", f"Expected phishing due to malicious attachment, got {res3.verdict}"
    print("[PASS] TEST 3 PASSED: Dangerous attachment alone triggered PHISHING verdict!")

    # Test 4: Macro Document (.xlsm)
    print("\n--- Test 4: Macro Document Attachment (.xlsm) ---")
    req4 = EmailAnalysisRequest(
        sender_name="Accounting",
        sender_email="accounting@company.com",
        subject="Monthly Remittance Breakdown",
        body="Please review the remittance calculations in the attached spreadsheet.",
        links=[],
        attachments=["remittance_statement.xlsm"],
        is_authenticated=True
    )
    res4 = analyze_email_hybrid(req4)
    print(f"Verdict: {res4.verdict} (Display: {res4.display_verdict})")
    print(f"Risk Category: {res4.risk_category}")
    assert any(ind.type == "MACRO_ATTACHMENT" for ind in res4.indicators), "Expected macro attachment indicator"
    print("[PASS] TEST 4 PASSED: Macro attachment correctly flagged!")

    # Test 5: RTLO Unicode Extension Spoofing
    print("\n--- Test 5: RTLO Unicode Extension Spoofing ---")
    req5 = EmailAnalysisRequest(
        sender_name="Unknown",
        sender_email="user@example.com",
        subject="Important document",
        body="See file",
        links=[],
        attachments=["financial_\u202eexe.pdf"],
        is_authenticated=True
    )
    res5 = analyze_email_hybrid(req5)
    print(f"Verdict: {res5.verdict}")
    assert res5.verdict == "phishing"
    assert any(ind.type == "RTLO_ATTACHMENT" for ind in res5.indicators)
    print("[PASS] TEST 5 PASSED: RTLO Unicode spoofing caught!")

    print("\n" + "=" * 60)
    print("ALL TESTS PASSED SUCCESSFULLY!")
    print("=" * 60)

if __name__ == "__main__":
    run_tests()
