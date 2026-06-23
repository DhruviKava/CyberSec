# 🔐 CyberSec IDS — Network Threat Detector

> A premium, end-to-end Machine Learning pipeline that detects malicious network traffic using **Random Forest** (supervised) and **Isolation Forest** (unsupervised) classifiers. Served via a content-negotiated **Flask REST API** with a real-time, glassmorphism **SOC Web Dashboard**.

---
<img width="1849" height="954" alt="Main_screen" src="https://github.com/user-attachments/assets/360a199c-f994-45b5-94dd-4b4290981f3d" />


<img width="1849" height="954" alt="Normal_traffic" src="https://github.com/user-attachments/assets/f10429df-14b2-48a5-a96f-1d699d58bff7" />

<img width="1849" height="954" alt="DDOS_SYN_flood" src="https://github.com/user-attachments/assets/62a87afd-1647-4e26-80b8-1b1af465a381" />

<img width="1849" height="954" alt="Ping_of_Death" src="https://github.com/user-attachments/assets/bcfd1790-679a-4b55-8dd0-1e93e24c9617" />

<img width="1849" height="954" alt="Port_scanning_UDP" src="https://github.com/user-attachments/assets/98d42490-7046-4fdf-bcb5-287ada125465" />


## 🗺️ High-Level Architecture

Below is the chronological sequence of the data pipeline, from exploratory research to live production hosting:

```mermaid
flowchart TD
    A[data/network_data.csv] -->|1. Data Exploration| B[notebooks/01_eda.ipynb]
    A -->|2. Model Prototyping| C[notebooks/02_train_evaluate.ipynb]
    A -->|3. Feature Selection| D[notebooks/03_shap_explain.ipynb]
    
    A -->|4. Production Pipeline| E[train.py]
    E -->|Preprocesses & Trains| F[models/*.pkl]
    
    F -->|5. Loaded into Memory| G[app/main.py]
    H[User Web Dashboard] -->|6. AJAX HTTP POST /predict| G
    G -->|7. JSON Response| H
```

---

## 🧠 Key Features

- **Hybrid Intelligence Models:** 
  - **Supervised Classifier (Random Forest):** Classifies connections into `normal` or `attack` classes with high precision.
  - **Unsupervised Anomaly Detector (Isolation Forest):** Measures structural distance to flag unusual patterns/zero-day attacks, even if they don't match known signatures.
- **Glassmorphism Web Dashboard:** An interactive Security Operations Center (SOC) style dashboard featuring:
  - **Dynamic Preset Cards:** Instant buttons to auto-populate features for typical traffic types (*Normal Web*, *DDoS*, *Port Scanning*, *Ping of Death*).
  - **Real-Time AJAX Communication:** Submits data and updates UI outputs without full-page reloads.
  - **Visual Gauges:** Glowing radial confidence meters, anomaly scoring indicators, and alert banners.
- **Content Negotiation:** The root URL (`/`) returns a clean JSON metadata response for automation scripts (e.g. `curl`) and serves the interactive dashboard for web browsers.

---

## 🛠️ Technological Stack

- **Core & Web Logic:** Python, Flask, Gunicorn (production server), Jinja2 templates.
- **Machine Learning & Math:** Scikit-Learn, Pandas, NumPy, Joblib, SHAP (explainable AI).
- **User Interface:** jQuery, HTML5, Custom Vanilla CSS (Glassmorphism design system), Outfit & Plus Jakarta Sans Google Fonts, FontAwesome Icons.

---

## 🗂 Project Directory Structure

```text
network-threat-detector/
├── data/
│   └── network_data.csv          # NSL-KDD-style connection dataset
├── notebooks/
│   ├── 01_eda.ipynb              # Exploratory Data Analysis
│   ├── 02_train_evaluate.ipynb   # Model prototyping & evaluation
│   └── 03_shap_explain.ipynb     # SHAP model explainability
├── app/
│   ├── templates/
│   │   └── index.html            # SOC Dashboard UI
│   └── main.py                   # Flask API & Routing
├── models/
│   ├── rf_model.pkl              # Saved Random Forest Classifier
│   ├── iso_model.pkl             # Saved Isolation Forest
│   ├── scaler.pkl                # Saved StandardScaler
│   ├── label_encoder.pkl         # Saved Categorical Encoder
│   └── features.pkl              # Saved Feature Order List
├── train.py                      # Training & Serialization pipeline
├── requirements.txt              # Project packages list
└── README.md                     # Main documentation
```

---

## 🚀 Quick Start (Local Run)

### 1. Installation

Clone this repository and install dependencies inside a virtual environment:

```bash
# Clone the repository
https://github.com/DhruviKava/CyberSec.git
cd CyberSec

# Create and activate virtual environment
python3 -m venv netdet
source netdet/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Run the Training Pipeline

If you want to train the models from scratch on the raw dataset:

```bash
python train.py
```
This updates the binaries in the `models/` directory.

### 3. Run the Server

Start the Flask server:

```bash
python app/main.py
```
* **Interactive UI:** Navigate to `http://localhost:5000` in your web browser.
* **REST API:** Automated clients can call endpoints directly.

---

## 📡 REST API Endpoints

### `POST /predict`
Submits raw connection metrics to the pipeline for classification.

**Request Payload:**
```json
{
  "duration": 0.05,
  "protocol_type": "icmp",
  "src_bytes": 65500,
  "dst_bytes": 0,
  "count": 300,
  "srv_count": 1,
  "same_srv_rate": 0.05,
  "diff_srv_rate": 0.95,
  "dst_host_count": 255,
  "dst_host_srv_count": 2
}
```

**cURL Command Example:**
```bash
curl -X POST http://localhost:5000/predict \
  -H "Content-Type: application/json" \
  -d '{"duration": 0.05, "protocol_type": "icmp", "src_bytes": 65500, "dst_bytes": 0, "count": 300, "srv_count": 1, "same_srv_rate": 0.05, "diff_srv_rate": 0.95, "dst_host_count": 255, "dst_host_srv_count": 2}'
```

**JSON Response Output:**
```json
{
  "prediction": "attack",
  "confidence": 98.0,
  "attack_probability": 98.0,
  "anomaly_detected": true,
  "anomaly_score": -0.1873,
  "models_used": ["RandomForest", "IsolationForest"]
}
```

---

