# Vanguard AI-NIDS

Vanguard is an AI-powered Network Intrusion Detection System (NIDS) utilizing a two-stage XGBoost architecture trained on the CICIDS2017 dataset.

## Features
- **Two-Stage Detection:** Stage 1 separates Benign from Malicious traffic. Stage 2 classifies the specific attack vector (DoS, PortScan, BruteForce, WebAttack, Botnet, Infiltration).
- **Explainable AI:** Integrated SHAP (SHapley Additive exPlanations) values to explain exactly why a flow was classified as an attack.
- **Modern UI:** Built with Streamlit featuring a premium glassmorphism design.
- **Automated Fallback:** Automatically generates fallback dummy models if the original `xgboost.pkl` models are missing, ensuring the dashboard never crashes during demonstrations.

## Installation & Setup

1. **Prerequisites**: Python 3.9+ is recommended.
2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
   *(Note: PCAP processing requires `nfstream`. If you are on Windows, `nfstream` is not officially supported. You can run the application in WSL2 or Ubuntu to enable PCAP parsing).*

## Running the Application

**On Windows:**
Double-click `start.bat` or run:
```cmd
start.bat
```

**On Linux/Ubuntu/WSL2:**
```bash
bash start.sh
```
Or manually run:
```bash
streamlit run app.py
```

## Using the System

### 1. Uploading Data
- **CSV Format:** Upload a CSV file exported from CICFlowMeter or matched to the exact 78 features of CICIDS2017. Missing features will be automatically padded with zeros.
- **PCAP Format:** Upload a raw `.pcap` capture file. The `feature_extractor.py` will attempt to parse it utilizing `nfstream` and map fundamental metrics to CICIDS2017 standards (requires Linux/WSL2 environment).

### 2. Exploring Results
- **Dashboard:** The main page displays an overview of detected malicious flows, comprehensive logs, and interactive charts.
- **Deep Inspection:** Select a flow index to generate a local SHAP waterfall chart explaining the specific network attributes that caused the alert.
- **Global SHAP:** Review global feature importance.
- **Performance:** Analyze Sprint 3 and 6 model validation metrics.

## Models
Place your pre-trained models inside the `models/` directory:
- `models/xgboost.pkl` (Stage 1 Binary)
- `models/stage2_xgboost.pkl` (Stage 2 Multi-class)
- `models/stage2_label_encoder.pkl` (Label Encoder)
- `models/minmax_scaler.pkl` (MinMaxScaler object)

*If these are missing, Vanguard will gracefully auto-generate functional mock models for demonstration purposes.*

## Local Testing
To ensure the pipelines are operational without booting the UI:
```bash
python test_local.py
```
