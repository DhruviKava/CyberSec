"""
train.py — Train and save the Network Intrusion Detection models.
Run this first before starting the Flask API.

Usage:
    python train.py
"""

import pandas as pd
import numpy as np
import joblib
import os
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score

# ── paths ────────────────────────────────────────────────────────────────────
DATA_PATH   = os.path.join(os.path.dirname(__file__), 'data', 'network_data.csv')
MODELS_DIR  = os.path.join(os.path.dirname(__file__), 'models')
os.makedirs(MODELS_DIR, exist_ok=True)

# ── load & encode ────────────────────────────────────────────────────────────
df = pd.read_csv(DATA_PATH)
print(f"[+] Loaded dataset: {df.shape}")
print(f"    Normal: {(df.label=='normal').sum()}  |  Attack: {(df.label=='attack').sum()}")

le = LabelEncoder()
df['protocol_encoded'] = le.fit_transform(df['protocol_type'])

FEATURES = [
    'duration', 'src_bytes', 'dst_bytes', 'count', 'srv_count',
    'same_srv_rate', 'diff_srv_rate', 'dst_host_count', 'dst_host_srv_count',
    'protocol_encoded'
]

X = df[FEATURES]
y = (df['label'] == 'attack').astype(int)

# ── scale & split ────────────────────────────────────────────────────────────
scaler   = StandardScaler()
X_scaled = scaler.fit_transform(X)
X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y, test_size=0.2, random_state=42, stratify=y
)

# ── Random Forest ─────────────────────────────────────────────────────────────
print("\n[+] Training Random Forest ...")
rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
rf.fit(X_train, y_train)
y_pred = rf.predict(X_test)
print(classification_report(y_test, y_pred, target_names=['normal', 'attack']))
print(f"    ROC-AUC: {roc_auc_score(y_test, rf.predict_proba(X_test)[:,1]):.4f}")

# ── Isolation Forest ──────────────────────────────────────────────────────────
print("[+] Training Isolation Forest ...")
iso = IsolationForest(contamination=0.3, random_state=42)
iso.fit(X_train)

# ── save artifacts ────────────────────────────────────────────────────────────
joblib.dump(rf,       os.path.join(MODELS_DIR, 'rf_model.pkl'))
joblib.dump(iso,      os.path.join(MODELS_DIR, 'iso_model.pkl'))
joblib.dump(scaler,   os.path.join(MODELS_DIR, 'scaler.pkl'))
joblib.dump(le,       os.path.join(MODELS_DIR, 'label_encoder.pkl'))
joblib.dump(FEATURES, os.path.join(MODELS_DIR, 'features.pkl'))
print("\n[+] Models saved to ./models/")

# ── confusion matrix plot ─────────────────────────────────────────────────────
cm = confusion_matrix(y_test, y_pred)
plt.figure(figsize=(5, 4))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
            xticklabels=['normal', 'attack'],
            yticklabels=['normal', 'attack'])
plt.title('Confusion Matrix — Random Forest')
plt.ylabel('Actual')
plt.xlabel('Predicted')
plt.tight_layout()
plt.savefig(os.path.join(MODELS_DIR, 'confusion_matrix.png'), dpi=150)
print("[+] Confusion matrix saved to ./models/confusion_matrix.png")
