import os
import json
import pytest
from app.ml.model import predict_email_category, predict_phishing
from app.forensics.header_analyzer import analyze_email_headers
from app.forensics.fraud_scorer import compute_fused_fraud_score

# =====================================================================
# 1. MULTI-CLASS ML CLASSIFIER INFERENCE TESTS
# =====================================================================

def test_multiclass_category_bec_fraud():
    """Verify ML model identifies BEC and wire transfer fraud lures."""
    text = "URGENT: Please process the revised wire transfer for invoice #99281 to the new vendor account immediately."
    res = predict_email_category(text)
    assert res["category"] == "bec_fraud"
    assert res["is_threat"] is True
    assert res["confidence"] >= 0.60
    assert "bec_fraud" in res["probabilities"]

def test_multiclass_category_phishing():
    """Verify ML model identifies credential-harvesting phishing patterns."""
    text = "Your Microsoft 365 password expires today. Click here to confirm your current password and prevent account suspension."
    res = predict_email_category(text)
    assert res["category"] == "phishing"
    assert res["is_threat"] is True
    assert res["confidence"] >= 0.60

def test_multiclass_category_impersonation():
    """Verify ML model identifies brand and identity impersonation notices."""
    text = "PayPal Security Alert: Unauthorized activity detected on your PayPal balance. Verify your identity now."
    res = predict_email_category(text)
    assert res["category"] == "impersonation"
    assert res["is_threat"] is True

def test_multiclass_category_legitimate():
    """Verify ML model identifies benign corporate correspondence."""
    text = "Hi team, please find attached the revised project roadmap and sprint schedule for Q3. Looking forward to our sync at 3 PM."
    res = predict_email_category(text)
    assert res["category"] == "legitimate"
    assert res["is_threat"] is False
    assert res["threat_probability"] < 0.40

def test_binary_backwards_compatibility():
    """Verify predict_phishing provides backwards compatibility for existing components."""
    clean_res = predict_phishing("Meeting notes from yesterday's retrospective session.")
    assert clean_res["is_phishing"] is False
    assert clean_res["error"] is None

    threat_res = predict_phishing("URGENT: Wire transfer required today for confidential acquisition.")
    assert threat_res["is_phishing"] is True
    assert threat_res["confidence"] > 0.50
    assert threat_res["category"] == "bec_fraud"

# =====================================================================
# 2. FRAUD SCORE FUSION & PER-FACTOR WEIGHT TESTS
# =====================================================================

def test_fraud_score_weights_and_breakdown(load_fixture):
    """Verify fraud score correctly fuses all 5 weighted factors into 0-100 range."""
    eml_bytes = load_fixture("legitimate_email.eml")
    result = analyze_email_headers(eml_bytes)
    assert result.fraud_score is not None
    fs = result.fraud_score

    # Check that per-factor weights sum to 1.0 (25% + 25% + 20% + 15% + 15%)
    total_weights = (
        fs.nlp_linguistic_factor.weight +
        fs.header_transport_factor.weight +
        fs.authentication_factor.weight +
        fs.domain_intel_factor.weight +
        fs.ip_reputation_factor.weight
    )
    assert round(total_weights, 2) == 1.00

    # Clean email should have low score and LOW risk tier
    assert fs.overall_score < 30
    assert fs.risk_tier == "LOW"
    assert fs.predicted_category == "legitimate"

def test_fraud_score_on_bec_invoice_fixture(load_fixture):
    """Verify BEC invoice fraud email triggers high header transport and fraud score."""
    eml_bytes = load_fixture("bec_invoice_fraud.eml")
    result = analyze_email_headers(eml_bytes)
    assert result.fraud_score is not None
    fs = result.fraud_score

    assert fs.overall_score >= 50
    assert fs.predicted_category == "bec_fraud"
    # Reply-To diversion must contribute points to header transport factor
    assert fs.header_transport_factor.score >= 15.0
    assert fs.header_transport_factor.status in ["WARNING", "CRITICAL"]

def test_fraud_score_on_tor_origin_fixture(load_fixture):
    """Verify Tor exit node origin triggers maximum IP reputation penalty."""
    eml_bytes = load_fixture("tor_origin.eml")
    result = analyze_email_headers(eml_bytes)
    assert result.fraud_score is not None
    fs = result.fraud_score

    # Max points for Tor exit node
    assert fs.ip_reputation_factor.score == 15.0
    assert fs.ip_reputation_factor.status == "CRITICAL"
    assert fs.risk_tier == "CRITICAL"

def test_training_report_file_integrity():
    """Verify training report was generated with required metrics and confusion matrix."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    report_path = os.path.join(base_dir, "app", "ml", "training_report.json")
    assert os.path.exists(report_path)

    with open(report_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert "accuracy" in data
    assert data["accuracy"] >= 0.90
    assert "classification_report" in data
    assert "confusion_matrix" in data
    assert len(data["confusion_matrix"]["labels"]) == 5
