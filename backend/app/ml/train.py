import os
import sys
import json
from datetime import datetime, timezone

# Ensure UTF-8 output on Windows console
if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib

# Setup paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_PATH = os.path.join(BASE_DIR, '..', 'datasets', 'emails.csv')
MODEL_PATH = os.path.join(BASE_DIR, 'ml', 'model.joblib')
VECTORIZER_PATH = os.path.join(BASE_DIR, 'ml', 'vectorizer.joblib')
REPORT_PATH = os.path.join(BASE_DIR, 'ml', 'training_report.json')

CATEGORIES = ["legitimate", "suspicious", "impersonation", "phishing", "bec_fraud"]

def train_model():
    print("🚀 Starting Multi-Class AI Threat Classifier Training...")
    
    # 1. Load Data
    if not os.path.exists(DATASET_PATH):
        print(f"❌ Error: Dataset not found at {DATASET_PATH}")
        return
        
    print(f"📊 Loading dataset from {DATASET_PATH}")
    df = pd.read_csv(DATASET_PATH)
    df.drop_duplicates(subset=['text'], inplace=True)
    print(f"🧹 Unique samples after deduplication: {len(df)}")
    
    # Verify categories exist
    if 'category' not in df.columns:
        print("⚠️ Warning: 'category' column missing. Mapping from label.")
        df['category'] = df['label'].map({0: 'legitimate', 1: 'phishing'})
        
    print(f"📈 Class Distribution:\n{df['category'].value_counts()}")
    
    X = df['text']
    y = df['category']
    
    # 2. Split Data (80% train, 20% test stratified)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"✂️  Data split: {len(X_train)} training samples, {len(X_test)} testing samples.")
    
    # 3. Feature Extraction (TF-IDF with unigrams & bigrams)
    print("🔤 Extracting TF-IDF features (unigram + bigram)...")
    vectorizer = TfidfVectorizer(
        stop_words='english',
        max_features=7500,
        ngram_range=(1, 2),
        sublinear_tf=True
    )
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)
    
    # 4. Train Model (Multi-Class Logistic Regression)
    print("🧠 Training Multi-Class Logistic Regression model with balanced class weights...")
    model = LogisticRegression(
        max_iter=1000,
        class_weight='balanced',
        random_state=42
    )
    model.fit(X_train_vec, y_train)
    
    # 5. Evaluate Model
    print("📈 Evaluating model on test set...")
    y_pred = model.predict(X_test_vec)
    acc = accuracy_score(y_test, y_pred)
    
    # Classification Report
    cls_report_dict = classification_report(y_test, y_pred, output_dict=True, zero_division=0)
    cls_report_text = classification_report(y_test, y_pred, zero_division=0)
    
    # Confusion Matrix
    present_labels = sorted(list(set(y_test) | set(y_pred)))
    cm = confusion_matrix(y_test, y_pred, labels=present_labels)
    
    print("\n" + "="*50)
    print(f"🎯 Model Accuracy: {acc * 100:.2f}%")
    print("="*50)
    print(cls_report_text)
    
    print("🔍 Confusion Matrix:")
    print(f"Labels: {present_labels}")
    print(cm)
    
    # 6. Save Training Report
    report_data = {
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "total_samples": len(df),
        "train_samples": len(X_train),
        "test_samples": len(X_test),
        "accuracy": round(float(acc), 4),
        "classes": [str(c) for c in model.classes_],
        "classification_report": cls_report_dict,
        "confusion_matrix": {
            "labels": present_labels,
            "matrix": cm.tolist()
        }
    }
    
    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)
    print(f"📄 Detailed training report saved to {REPORT_PATH}")
    
    # 7. Save Model & Vectorizer
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    joblib.dump(vectorizer, VECTORIZER_PATH)
    print(f"✅ Model saved to {MODEL_PATH}")
    print(f"✅ Vectorizer saved to {VECTORIZER_PATH}")
    print("🎉 Training Complete! Server is ready with multi-class intelligence.")

if __name__ == "__main__":
    train_model()
