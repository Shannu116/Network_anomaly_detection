# Network Anomaly Detection System

A real-time network anomaly detection system using Machine Learning to identify suspicious network traffic patterns. This project uses the UNSW-NB15 dataset and implements a Gradient Boosting Classifier for high-accuracy threat detection.

## 🎯 Features

- **Real-time Packet Capture**: Live network traffic monitoring using Scapy
- **Machine Learning Detection**: Gradient Boosting Classifier with 87.31% accuracy
- **Flow-based Analysis**: Aggregates packets into network flows for better context
- **UNSW-NB15 Feature Extraction**: Extracts 42 standardized network flow features
- **Anomaly Alerting**: Real-time alerts with confidence scores and detailed statistics
- **Comprehensive Logging**: CSV and JSON logs for captured packets and detected anomalies
- **High Detection Rate**: 98.33% recall for attack detection

## 📊 Model Performance

| Metric | Value |
|--------|-------|
| **Training Accuracy** | 96.20% |
| **Testing Accuracy** | 87.31% |
| **Precision** | 82.14% |
| **Recall** | 98.33% |
| **F1-Score** | 89.51% |
| **ROC-AUC** | 98.37% |

Trained on **175,341 samples** and tested on **82,332 independent samples** from the UNSW-NB15 dataset.

## 🏗️ Architecture

```
Network Traffic → Packet Capture → Flow Aggregation → Feature Extraction → ML Model → Anomaly Alert
                      (Scapy)       (FlowTracker)      (42 Features)      (GB Clf)    (Logging)
```

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- Root/sudo privileges (for packet capture)
- Linux/macOS (Windows requires additional setup)

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/YOUR_USERNAME/Network-Anamoly-Detection.git
cd Network-Anamoly-Detection
```

2. **Create virtual environment**
```bash
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

### Usage

#### 1. Train the Model (Optional - Pre-trained model included)

```bash
python train_unsw_nb15.py
```

This will:
- Load the UNSW-NB15 training dataset
- Train and evaluate 3 ML models (Random Forest, Gradient Boosting, Extra Trees)
- Select the best model based on F1-score and ROC-AUC
- Save the trained model to `trained_models/`

#### 2. Test the Model

```bash
python test_model.py
```

Evaluates the model on the UNSW-NB15 test dataset and generates performance metrics.

#### 3. Run Live Detection

```bash
sudo .venv/bin/python3 live_anomaly_detection.py --interface wlan0 --threshold 0.7
```

**Options:**
- `--interface`: Network interface to monitor (e.g., `eth0`, `wlan0`)
- `--threshold`: Confidence threshold for alerts (0.0-1.0, default: 0.5)
- `--model`: Path to trained model (default: `trained_models/unsw_attack_detector.joblib`)
- `--filter`: BPF filter for packet capture (default: `ip`)
- `--log-dir`: Directory for log files (default: `logs`)

**Example:**
```bash
# Monitor WiFi interface with 70% confidence threshold
sudo .venv/bin/python3 live_anomaly_detection.py --interface wlan0 --threshold 0.7

# Monitor all IP traffic on eth0
sudo .venv/bin/python3 live_anomaly_detection.py --interface eth0 --filter "ip"

# High-confidence alerts only (90%+)
sudo .venv/bin/python3 live_anomaly_detection.py --threshold 0.9
```

#### 4. Predict on Custom Data

```bash
python predict_attacks.py
```

Demonstrates how to use the trained model for batch predictions.

## 📁 Project Structure

```
Network-Anamoly-Detection/
├── train_unsw_nb15.py              # Training script
├── test_model.py                   # Model evaluation script
├── live_anomaly_detection.py       # Real-time detection system
├── predict_attacks.py              # Batch prediction demo
├── requirements.txt                # Python dependencies
├── LIVE_DETECTION_GUIDE.md        # Detailed usage guide
│
├── UNSW_NB15_training-set.csv     # Training dataset (175,341 samples)
├── UNSW_NB15_testing-set.csv      # Testing dataset (82,332 samples)
│
├── trained_models/
│   ├── unsw_attack_detector.joblib # Trained model (4.7 MB)
│   └── unsw_training_report.json   # Training metrics
│
└── test_results/
    └── test_report.json            # Test performance metrics
```

## 🔍 How It Works

### 1. Flow Aggregation
The system groups packets into bidirectional flows using a 5-tuple key:
- Source IP + Port
- Destination IP + Port  
- Protocol

### 2. Feature Extraction
For each flow, 42 UNSW-NB15 features are extracted:
- **Basic Features**: Duration, protocol, service, state
- **Traffic Features**: Packet counts, byte counts, rate
- **Time Features**: TTL, inter-arrival times, jitter
- **TCP Features**: Window sizes, sequence numbers, RTT
- **Content Features**: Payload statistics
- **Connection Features**: Historical flow statistics

### 3. Anomaly Detection
The Gradient Boosting Classifier predicts whether a flow is:
- **Normal** (0): Legitimate network traffic
- **Anomaly** (1): Suspicious/malicious traffic

### 4. Alerting & Logging
When an anomaly is detected:
- **Console Alert**: Real-time notification with flow details
- **CSV Log**: `anomaly_log_TIMESTAMP.csv` with all flow features
- **JSON Log**: `session_TIMESTAMP.json` with session summary

## 📈 Datasets

### UNSW-NB15 Dataset
- **Source**: University of New South Wales, Australian Centre for Cyber Security
- **Size**: 257,673 records (175,341 training + 82,332 testing)
- **Features**: 42 network flow features
- **Classes**: Normal (0) and Attack (1)
- **Attack Types**: Fuzzers, Analysis, Backdoors, DoS, Exploits, Generic, Reconnaissance, Shellcode, Worms

**Dataset is included in this repository** for easy reproduction of results.

## 🛠️ Model Training Details

### Algorithm Selection
Three algorithms were evaluated:
1. **Random Forest**: Baseline ensemble method
2. **Gradient Boosting**: Best performer (selected)
3. **Extra Trees**: Alternative ensemble approach

### Preprocessing Pipeline
- **Numeric Features** (39): `SimpleImputer` → `StandardScaler`
- **Categorical Features** (3): `SimpleImputer` → `OneHotEncoder`
  - Protocol: tcp, udp, icmp, etc.
  - Service: http, dns, smtp, etc.
  - State: CON, FIN, INT, etc.

### Hyperparameters (Gradient Boosting)
```python
GradientBoostingClassifier(
    n_estimators=100,
    max_depth=10,
    learning_rate=0.1,
    random_state=42
)
```

## 🔒 Security Considerations

- **Root Privileges**: Packet capture requires sudo/root access
- **Privacy**: Be mindful of capturing sensitive traffic
- **Performance**: High-traffic networks may require optimization
- **False Positives**: Legitimate encrypted traffic may trigger alerts

## 📝 Logging

Logs are saved to the `logs/` directory (excluded from Git):

**Anomaly Logs** (`anomaly_log_TIMESTAMP.csv`):
- Timestamp, flow details, confidence score
- All 42 extracted features
- Source/destination IPs and ports

**Session Logs** (`session_TIMESTAMP.json`):
- Session start/end time
- Total packets captured
- Flows analyzed
- Anomalies detected
- Detection rate



### Ideas for Improvement
- [ ] Deep learning models (LSTM, CNN)
- [ ] Multi-class attack classification
- [ ] Web-based dashboard for monitoring
- [ ] Docker containerization
- [ ] Support for additional datasets (CIC-IDS, Bot-IoT)
- [ ] Payload inspection and DPI features
- [ ] Integration with SIEM systems


## 🙏 Acknowledgments

- **UNSW-NB15 Dataset**: Australian Centre for Cyber Security (ACCS)
- **Scapy**: Packet manipulation library
- **scikit-learn**: Machine learning framework

