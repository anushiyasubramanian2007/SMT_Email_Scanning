import os
from typing import Dict, Any, Optional
import joblib

# Global variables to hold the loaded model in memory
_model = None
_vectorizer = None

def _load_model():
    global _model, _vectorizer
    if _model is not None and _vectorizer is not None:
        return
        
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    MODEL_PATH = os.path.join(BASE_DIR, 'model.joblib')
    VECTORIZER_PATH = os.path.join(BASE_DIR, 'vectorizer.joblib')
    
    if os.path.exists(MODEL_PATH) and os.path.exists(VECTORIZER_PATH):
        try:
            _model = joblib.load(MODEL_PATH)
            _vectorizer = joblib.load(VECTORIZER_PATH)
            print("AI Multi-Class Model loaded successfully.")
        except Exception as e:
            print(f"Error loading model: {e}")
    else:
        print("Warning: AI Model files not found. Please run train.py first.")

def predict_email_category(text: str) -> Dict[str, Any]:
    """
    Takes an email text and returns multi-class threat prediction:
    Categories: legitimate, suspicious, impersonation, phishing, bec_fraud
    """
    _load_model()
    
    if _model is None or _vectorizer is None:
        return {
            "category": "unknown",
            "confidence": 0.0,
            "is_threat": False,
            "threat_probability": 0.0,
            "probabilities": {},
            "error": "Model not loaded"
        }
        
    try:
        vec = _vectorizer.transform([text])
        probs = _model.predict_proba(vec)[0]
        classes = list(_model.classes_)
        
        prob_dict = {str(c): round(float(p), 4) for c, p in zip(classes, probs)}
        best_idx = int(probs.argmax())
        best_category = str(classes[best_idx])
        best_confidence = round(float(probs[best_idx]), 4)
        
        legit_prob = prob_dict.get("legitimate", 0.0)
        threat_prob = round(float(1.0 - legit_prob), 4)
        
        return {
            "category": best_category,
            "confidence": best_confidence,
            "is_threat": best_category != "legitimate",
            "threat_probability": threat_prob,
            "probabilities": prob_dict,
            "error": None
        }
    except Exception as e:
        return {
            "category": "unknown",
            "confidence": 0.0,
            "is_threat": False,
            "threat_probability": 0.0,
            "probabilities": {},
            "error": str(e)
        }

def predict_phishing(text: str) -> Dict[str, Any]:
    """
    Backwards-compatible interface for binary detection endpoints.
    """
    cat_res = predict_email_category(text)
    if cat_res.get("error"):
        return {"is_phishing": False, "confidence": 0.0, "error": cat_res["error"]}
        
    return {
        "is_phishing": cat_res["is_threat"],
        "confidence": cat_res["threat_probability"],
        "category": cat_res["category"],
        "category_probabilities": cat_res["probabilities"],
        "error": None
    }
