from flask import Flask, request, jsonify, render_template
import joblib
import numpy as np
import os

app = Flask(__name__)

# Load models
BASE = os.path.join(os.path.dirname(__file__), '..', 'models')
rf_model   = joblib.load(os.path.join(BASE, 'rf_model.pkl'))
iso_model  = joblib.load(os.path.join(BASE, 'iso_model.pkl'))
scaler     = joblib.load(os.path.join(BASE, 'scaler.pkl'))
le         = joblib.load(os.path.join(BASE, 'label_encoder.pkl'))
features   = joblib.load(os.path.join(BASE, 'features.pkl'))

PROTOCOL_MAP = {'tcp': 0, 'udp': 1, 'icmp': 2}

@app.route('/', methods=['GET'])
def index():
    if request.accept_mimetypes.accept_html:
        return render_template('index.html')
    return jsonify({
        "service": "Network Intrusion Detection API",
        "endpoints": {
            "POST /predict": "Classify a network connection as normal or attack",
            "GET  /health":  "Health check"
        },
        "example_input": {
            "duration": 0.0,
            "protocol_type": "tcp",
            "src_bytes": 491,
            "dst_bytes": 0,
            "count": 2,
            "srv_count": 2,
            "same_srv_rate": 1.0,
            "diff_srv_rate": 0.0,
            "dst_host_count": 150,
            "dst_host_srv_count": 25
        }
    })

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok"})

@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON body provided"}), 400

    try:
        proto = data.get('protocol_type', 'tcp').lower()
        protocol_encoded = PROTOCOL_MAP.get(proto, 0)

        row = [
            float(data.get('duration', 0)),
            float(data.get('src_bytes', 0)),
            float(data.get('dst_bytes', 0)),
            float(data.get('count', 1)),
            float(data.get('srv_count', 1)),
            float(data.get('same_srv_rate', 1.0)),
            float(data.get('diff_srv_rate', 0.0)),
            float(data.get('dst_host_count', 100)),
            float(data.get('dst_host_srv_count', 100)),
            float(protocol_encoded)
        ]

        X = np.array(row).reshape(1, -1)
        X_scaled = scaler.transform(X)

        # Random Forest prediction
        rf_pred  = int(rf_model.predict(X_scaled)[0])
        rf_proba = rf_model.predict_proba(X_scaled)[0].tolist()

        # Isolation Forest anomaly score (-1 = anomaly, 1 = normal)
        iso_pred  = int(iso_model.predict(X_scaled)[0])
        iso_score = float(iso_model.decision_function(X_scaled)[0])

        label = "attack" if rf_pred == 1 else "normal"
        anomaly = iso_pred == -1

        return jsonify({
            "prediction":       label,
            "confidence":       round(max(rf_proba) * 100, 2),
            "attack_probability": round(rf_proba[1] * 100, 2),
            "anomaly_detected": anomaly,
            "anomaly_score":    round(iso_score, 4),
            "models_used":      ["RandomForest", "IsolationForest"]
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
