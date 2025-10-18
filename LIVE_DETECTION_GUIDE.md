# Live Network Anomaly Detection System

## Overview
Real-time network traffic monitoring and anomaly detection using the trained UNSW-NB15 Gradient Boosting model.

**Performance:** 87.31% accuracy, 98.33% attack detection rate

---

## How It Works

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Network    │ --> │   Capture    │ --> │   Extract    │ --> │   Predict    │
│   Traffic    │     │   Packets    │     │   Features   │     │   Anomaly    │
└──────────────┘     └──────────────┘     └──────────────┘     └──────────────┘
                            ↓                      ↓                     ↓
                        Scapy              UNSW-NB15           Trained Model
                                          42 Features          (Gradient Boost)
```

### Process:
1. **Packet Capture**: Uses Scapy to capture live network packets
2. **Flow Tracking**: Groups packets into bidirectional flows
3. **Feature Extraction**: Converts flows into UNSW-NB15 format (42 features)
4. **Anomaly Detection**: Trained model predicts if traffic is benign or attack
5. **Alerting**: Displays detailed alerts for detected anomalies

---

## Installation

### 1. Install Scapy
```bash
pip install scapy
```

### 2. Verify Model Exists
```bash
ls trained_models/unsw_attack_detector.joblib
```

---

## Usage

### Basic Usage (requires sudo)
```bash
sudo python3 live_anomaly_detection.py
```

### Specify Network Interface
```bash
sudo python3 live_anomaly_detection.py --interface eth0
```

### Adjust Detection Threshold
```bash
# Lower threshold = more sensitive (more alerts)
# Higher threshold = less sensitive (fewer alerts)
sudo python3 live_anomaly_detection.py --threshold 0.5
```

### Filter Specific Traffic
```bash
# Only capture HTTP traffic
sudo python3 live_anomaly_detection.py --filter "tcp port 80"

# Only capture SSH traffic
sudo python3 live_anomaly_detection.py --filter "tcp port 22"

# Capture specific IP
sudo python3 live_anomaly_detection.py --filter "host 192.168.1.100"
```

### Full Options
```bash
sudo python3 live_anomaly_detection.py \
  --model trained_models/unsw_attack_detector.joblib \
  --interface wlan0 \
  --filter "ip" \
  --threshold 0.7
```

---

## Command Options

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--model` | - | `trained_models/unsw_attack_detector.joblib` | Path to trained model |
| `--interface` | `-i` | All interfaces | Network interface to monitor |
| `--filter` | `-f` | `ip` | BPF filter for packet capture |
| `--threshold` | `-t` | `0.7` | Detection threshold (0.0-1.0) |

---

## Extracted Features (UNSW-NB15 Format)

The system extracts 42 features from live traffic:

### Flow-Based Features:
- **Duration**: Flow duration in seconds
- **Packet counts**: Forward/backward packets (`spkts`, `dpkts`)
- **Byte counts**: Forward/backward bytes (`sbytes`, `dbytes`)
- **Rate**: Packets per second

### Statistical Features:
- **Mean packet sizes**: Average packet size per direction
- **Inter-arrival times**: Time between packets
- **Jitter**: Standard deviation of inter-arrival times

### Protocol Features:
- **Protocol**: TCP, UDP, ICMP
- **State**: Connection state (FIN, CON, etc.)
- **Flags**: TCP flags (SYN, FIN, RST, etc.)

### Advanced Features:
- **Load**: Bits per second per direction
- **Window sizes**: TCP window information
- **Service**: Port-based service detection
- **Connection metrics**: Cross-flow statistics

---

## Sample Output

### Normal Operation:
```
================================================================================
🔍 LIVE NETWORK ANOMALY DETECTION
================================================================================
Interface:  wlan0
Filter:     ip
Threshold:  0.70
Model:      Gradient Boosting (87.31% accuracy)

Press Ctrl+C to stop...
================================================================================

📊 Stats: 1523 pkts | 45 flows | 2 anomalies | 152.3 pps
```

### When Anomaly Detected:
```
================================================================================
🚨 ANOMALY DETECTED!
================================================================================
Time:        2025-10-18 16:30:45
Flow:        192.168.1.100:54321-192.168.1.1:80-tcp
Source:      192.168.1.100
Destination: 192.168.1.1
Protocol:    tcp
Confidence:  94.5%
Duration:    5.23s
Packets:     156 fwd, 142 bwd
Bytes:       45123 fwd, 892341 bwd
Rate:        57.01 pkt/s
================================================================================
```

---

## Performance Characteristics

### Detection Capabilities:
- ✅ **High Attack Detection**: 98.33% recall (catches most attacks)
- ✅ **Fast Processing**: Can handle hundreds of packets per second
- ✅ **Real-time Alerts**: Immediate notification of anomalies
- ⚠️ **False Positives**: ~26% (security-focused, errs on caution)

### System Requirements:
- **CPU**: Moderate (feature extraction + ML inference)
- **Memory**: ~100MB + flow state (grows with active flows)
- **Permissions**: Root/sudo required for packet capture
- **Network**: Promiscuous mode for full traffic visibility

---

## Limitations & Notes

### Feature Approximations:
1. **Simplified Features**: Some UNSW-NB15 features require deep packet inspection
2. **Direction Detection**: Basic heuristic (may not always be accurate)
3. **Service Detection**: Limited without full payload analysis
4. **Cross-flow Metrics**: Simplified (would need global state)

### Known Limitations:
- Cannot analyze encrypted payload (HTTPS, SSH content)
- Limited to IP traffic only
- Flow timeout may miss long-lived connections
- Performance depends on network speed

### Recommendations:
1. **Start with higher threshold** (0.7-0.8) to reduce false positives
2. **Monitor specific interfaces** to reduce noise
3. **Use BPF filters** to focus on suspicious traffic
4. **Log alerts** for later analysis (add logging if needed)

---

## Troubleshooting

### Permission Denied:
```bash
# Must run with sudo
sudo python3 live_anomaly_detection.py
```

### No Packets Captured:
```bash
# Check available interfaces
ip link show

# Try specific interface
sudo python3 live_anomaly_detection.py --interface eth0

# Check if scapy is installed
python3 -c "import scapy; print('OK')"
```

### Model Not Found:
```bash
# Verify model exists
ls -lh trained_models/unsw_attack_detector.joblib

# If missing, retrain
python3 train_unsw_nb15.py
```

### Too Many Alerts:
```bash
# Increase threshold (less sensitive)
sudo python3 live_anomaly_detection.py --threshold 0.85
```

### Too Few Alerts:
```bash
# Decrease threshold (more sensitive)
sudo python3 live_anomaly_detection.py --threshold 0.5
```

---

## Future Improvements

1. **Alert Logging**: Save alerts to file/database
2. **Better Direction Detection**: Analyze initial SYN to determine flow direction
3. **Payload Analysis**: Deep packet inspection for service detection
4. **Cross-flow Features**: Track connections across flows
5. **Performance Optimization**: Batch predictions for efficiency
6. **Visualization Dashboard**: Real-time monitoring UI
7. **Integration**: Export to SIEM systems

---

## Example Use Cases

### 1. Monitor Local Network
```bash
sudo python3 live_anomaly_detection.py --interface eth0
```

### 2. Detect Port Scans
```bash
sudo python3 live_anomaly_detection.py --filter "tcp[tcpflags] & (tcp-syn) != 0"
```

### 3. Monitor Web Traffic
```bash
sudo python3 live_anomaly_detection.py --filter "tcp port 80 or tcp port 443"
```

### 4. Watch Specific Host
```bash
sudo python3 live_anomaly_detection.py --filter "host 192.168.1.50"
```

---

## Quick Start Checklist

- [ ] Install scapy: `pip install scapy`
- [ ] Verify model exists: `ls trained_models/`
- [ ] Run with sudo: `sudo python3 live_anomaly_detection.py`
- [ ] Monitor output for anomalies
- [ ] Adjust threshold if needed
- [ ] Press Ctrl+C to stop

---

**Created:** October 18, 2025  
**Model:** Gradient Boosting (87.31% accuracy)  
**Detection Rate:** 98.33% (attacks)  
**Status:** Ready for deployment
