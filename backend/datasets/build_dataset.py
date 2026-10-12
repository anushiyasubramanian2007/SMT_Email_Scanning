import os
import sys
import csv
import random

if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DATASET_FILE = os.path.join(BASE_DIR, "emails.csv")

# 1. Representative templates and phrases for each category
LEGITIMATE_TEMPLATES = [
    "Hi team, attached is the revised project roadmap for Q3 planning. Please review before our sync at 3 PM.",
    "Good morning. Can you please review the attached document and provide your feedback by end of day?",
    "Reminder: Team weekly standup meeting tomorrow at 10 AM in Conference Room B.",
    "The code for the new authentication feature has been merged into the develop branch.",
    "Please find attached the financial statements and quarterly audit report for your review.",
    "Schedule for campus recruitment drives and semester exams has been published on the student portal.",
    "Thanks for the update. I will review the architecture proposal and get back to you with comments.",
    "Don't forget to submit your timesheets and expense reports by Friday at 5 PM.",
    "Hi Alice, I will be working remotely tomorrow due to scheduled maintenance at the office.",
    "Here is the summary of the client meeting earlier today. Action items are assigned in Jira.",
    "Let's schedule a 15-minute quick call to discuss the sprint deliverables and QA progress.",
    "Attached is the vendor contract renewal draft. Legal has already signed off on the terms.",
    "All regular classes and lab sessions will resume as per schedule on Monday morning.",
    "Great job on the presentation today! The stakeholders were very impressed with the demo.",
    "Please submit your travel preferences and flight details for the upcoming conference in Chicago.",
    "The weekly engineering newsletter is now available on our internal wiki page.",
    "Here are the meeting notes and transcripts from yesterday's retrospective session.",
    "System maintenance window is scheduled for this Sunday from 2 AM to 4 AM EST. No downtime expected.",
    "Could you please share the API documentation and swagger specs for the billing service?",
    "Welcome to the team! Here is your onboarding checklist and links to your software credentials.",
    "I have updated the test cases for the integration suite. All unit tests are currently passing.",
    "Please review the attached slide deck before the executive briefing tomorrow morning.",
    "Following up on our discussion last week regarding the database migration timeline.",
    "The invoice for the cloud hosting services rendered last month has been received and approved by finance.",
    "Looking forward to catching up at the team lunch this Thursday at noon."
]

SUSPICIOUS_TEMPLATES = [
    "Congratulations! You have been selected to receive a $500 Amazon Gift Card. Claim your reward now!",
    "You have won the international charity lottery sweepstakes. Reply with your bank details to claim your prize.",
    "Your package could not be delivered due to an incorrect postal address. Click here to reschedule delivery.",
    "Exclusive offer: Earn up to $5,000 weekly working from home with no experience necessary. Sign up today!",
    "Congratulations! You are the lucky visitor of the day. Complete this 30-second survey to claim your prize.",
    "Your Walmart shopping voucher is expiring within 24 hours. Click the link below to redeem.",
    "Immediate reward: Claim your free cryptocurrency airdrop tokens by registering on our reward portal.",
    "Special promotional discount: 90% off all designer watches and luxury goods for the next 2 hours only!",
    "You have an unclaimed cash package waiting at customs. Provide your delivery coordinates immediately.",
    "Winner notification: Your email address was selected in our computer ballot drawing for $100,000 USD."
]

IMPERSONATION_TEMPLATES = [
    "PayPal Security Alert: Unauthorized activity detected on your PayPal balance. Verify your identity now to prevent account suspension.",
    "Your Amazon Prime subscription has been suspended due to a billing issue. Update your payment details immediately.",
    "Bank of America Security Notice: A hold has been placed on your checking account due to suspicious withdrawals.",
    "Microsoft Account Team: Unusual sign-in activity from an unrecognized IP address in Moscow, Russia. Secure your account now.",
    "Apple Support: Your iCloud storage has been locked. Verify your Apple ID credentials to restore your backup data.",
    "Netflix Billing Update: We were unable to authorize your monthly subscription payment. Update your credit card to keep watching.",
    "Chase Online Banking: We detected multiple failed login attempts on your account. Verify your identity to regain access.",
    "FedEx Delivery Alert: Tracking #FX-983120 is held at our distribution center. Confirm your identity to release shipment.",
    "DHL Express: Your shipment is pending clearance. Pay customs clearance duty of $4.99 online to schedule delivery.",
    "Wells Fargo Fraud Department: Immediate action required. Temporary restriction applied to your debit card."
]

PHISHING_TEMPLATES = [
    "Action Required: Your Microsoft 365 password expires today. Click here to keep your current password and prevent email disconnection.",
    "IT Helpdesk Alert: Storage quota exceeded. You have 14 quarantined inbound messages. Click here to review and release them.",
    "Important Document Shared: Sarah Jenkins shared 'Q3_Confidential_Financials.pdf' with you on SharePoint. Sign in to view document.",
    "Human Resources: The 2026 Employee Health & Benefits Enrollment is now open. Log in to your employee portal to select your plan.",
    "Security Verification Required: We detected login from Chrome on Windows 10. Click here if this was not you to terminate the session.",
    "DocuSign: Please review and electronically sign 'Confidential Non-Disclosure Agreement.pdf' using your email credentials.",
    "Your corporate email account will be deactivated within 6 hours due to server migration. Confirm your mailbox credentials now.",
    "Adobe Acrobat Cloud: An encrypted document has been sent to you. Enter your work email password to decrypt and view file.",
    "Google Workspace Alert: Your Google account password was recently changed. If you did not make this change, secure your account.",
    "Payroll Department: Please log in to the employee self-service portal to review your W-2 tax forms and direct deposit information."
]

BEC_FRAUD_TEMPLATES = [
    "URGENT: Confidential wire transfer instructions. Are you at your desk right now? We need to settle acquisition payment immediately.",
    "Revised Bank Coordinates: Please find our updated remittance details for invoice #INV-88219. Disregard previously registered account.",
    "Urgent Payment Diversion: Please process an outgoing wire transfer of $48,500 to vendor account today before banking cutoff.",
    "CEO Request: I am in a board meeting and cannot take calls. Please process an urgent foreign wire payment and send confirmation receipt.",
    "Vendor Remittance Update: Our primary bank is currently under audit. Please redirect all pending invoice disbursements to our new account.",
    "Confidential Acquisition: We are closing a private transaction today. Process the attached wire transfer and do not discuss with colleagues.",
    "Payroll Direct Deposit Change: Please update my bank account on file for upcoming payroll direct deposit to the following routing number.",
    "Invoice #48291 is overdue. Please remit wire payment immediately to avoid legal escalation and penalty charges.",
    "Attention Accounts Payable: Here are the revised banking details for our software license settlement. Confirm once wire is sent.",
    "Executive Authorization: Please initiate a wire transfer of $72,000 for emergency consulting services rendered this month."
]

def generate_variations(base_templates, target_count):
    """Generate diverse variations by combining subject lines, contextual modifiers, and salutations."""
    salutations = ["Hi,", "Hello,", "Dear User,", "Attention,", "Good morning,", "Urgent:"]
    closings = ["Best regards,", "Sincerely,", "Thank you,", "Corporate Security,", "Finance Department,"]
    results = []
    
    while len(results) < target_count:
        template = random.choice(base_templates)
        sal = random.choice(salutations)
        close = random.choice(closings)
        
        # Add random variations
        ref_id = random.randint(1000, 99999)
        var_text = f"{sal} {template} [Ref: #{ref_id}] {close}"
        results.append(var_text)
        
    return results[:target_count]

def build_dataset():
    print("🚀 Constructing Multi-Class Threat Dataset...")
    rows = []
    
    # 1. Legitimate (label=0, category='legitimate')
    legit_samples = generate_variations(LEGITIMATE_TEMPLATES, 250)
    for s in legit_samples:
        rows.append({"text": s, "label": 0, "category": "legitimate"})
        
    # 2. Suspicious (label=1, category='suspicious')
    susp_samples = generate_variations(SUSPICIOUS_TEMPLATES, 220)
    for s in susp_samples:
        rows.append({"text": s, "label": 1, "category": "suspicious"})
        
    # 3. Impersonation (label=1, category='impersonation')
    imp_samples = generate_variations(IMPERSONATION_TEMPLATES, 220)
    for s in imp_samples:
        rows.append({"text": s, "label": 1, "category": "impersonation"})
        
    # 4. Phishing (label=1, category='phishing')
    phish_samples = generate_variations(PHISHING_TEMPLATES, 250)
    for s in phish_samples:
        rows.append({"text": s, "label": 1, "category": "phishing"})
        
    # 5. BEC / Fraud (label=1, category='bec_fraud')
    bec_samples = generate_variations(BEC_FRAUD_TEMPLATES, 240)
    for s in bec_samples:
        rows.append({"text": s, "label": 1, "category": "bec_fraud"})
        
    random.seed(42)
    random.shuffle(rows)
    
    # Write to CSV
    with open(DATASET_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["text", "label", "category"])
        writer.writeheader()
        writer.writerows(rows)
        
    print(f"✅ Generated {len(rows)} samples across 5 categories in {DATASET_FILE}")

if __name__ == "__main__":
    build_dataset()
