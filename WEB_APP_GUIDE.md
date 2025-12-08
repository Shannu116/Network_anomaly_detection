# Network Anomaly Detection - Web Interface Guide

## Overview

This web-based GUI provides a real-time monitoring interface for the Network Anomaly Detection System. Built with FastAPI, it offers fast and efficient display of logs, alerts, and network statistics.

## Features

- **Real-time Dashboard**: Live updates of network anomalies and traffic statistics
- **WebSocket Support**: Instant notifications of new anomalies
- **Interactive Visualizations**: Charts and graphs showing attack distributions
- **Network Flow Monitoring**: Detailed view of all analyzed network flows
- **Alert Management**: Categorized alerts with severity levels (High, Medium, Low)
- **Model Information**: Display of model performance metrics
- **Responsive Design**: Mobile-friendly interface built with Bootstrap 5

## Installation

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

The web application requires:
- `fastapi` - Modern web framework
- `uvicorn` - ASGI server for FastAPI
- `websockets` - Real-time communication
- `python-multipart` - File upload support

### 2. Verify Directory Structure

Ensure the following directories exist:
```
Network_Anomaly_detection/
├── logs/                    # Anomaly logs and network flows
├── trained_models/          # Trained ML models
├── test_results/           # Model test results
└── web_app.py              # Web application
```

## Running the Web Application

### Method 1: Using the Startup Script (Recommended)

```bash
chmod +x start_web_app.sh
./start_web_app.sh
```

### Method 2: Manual Start

```bash
python3 web_app.py
```

### Method 3: With Custom Configuration

```bash
uvicorn web_app:app --host 0.0.0.0 --port 8000 --reload
```

## Accessing the Dashboard

Once the server is running, open your web browser and navigate to:
```
http://localhost:8000
```

For remote access (from another machine on the network):
```
http://<server-ip>:8000
```

## Dashboard Components

### 1. Statistics Cards
- **Total Anomalies**: Count of all detected anomalies
- **Network Flows**: Total number of analyzed flows
- **Attack Types**: Number of unique attack categories
- **Model Accuracy**: Current model performance

### 2. Recent Alerts
- Real-time display of detected anomalies
- Color-coded by severity:
  - 🔴 **High** (confidence ≥ 90%)
  - 🟡 **Medium** (confidence 70-90%)
  - 🟢 **Low** (confidence < 70%)
- Shows source/destination IPs and timestamps

### 3. Attack Type Distribution
- Interactive pie chart showing attack categories
- Hover for detailed statistics
- Updates automatically with new detections

### 4. Recent Network Flows
- Table view of analyzed traffic
- Displays:
  - Timestamps
  - Source and destination IPs
  - Protocol information
  - Packet and byte counts
  - Anomaly status

### 5. Model Information
- Model type and architecture
- Performance metrics (accuracy, precision, recall, F1-score)
- Training date and configuration

### 6. System Logs
- Real-time system status
- Connection monitoring
- Update timestamps

## API Endpoints

The web application provides RESTful API endpoints:

### Statistics
```
GET /api/statistics
```
Returns overall system statistics.

### Latest Anomalies
```
GET /api/anomalies/latest?limit=50
```
Get the most recent anomalies (default: 50).

### Network Flows
```
GET /api/flows/latest?limit=100
```
Get recent network flows (default: 100).

### Model Information
```
GET /api/model/info
```
Get trained model details and metrics.

### Test Results
```
GET /api/test/results
```
Get model testing results.

### WebSocket Connection
```
WebSocket /ws
```
Real-time updates channel for new anomalies.

## Integration with Live Detection

To use the web interface with live packet capture:

### 1. Start the Web Application
```bash
python3 web_app.py
```

### 2. In Another Terminal, Start Live Detection
```bash
sudo python3 live_anomaly_detection.py --interface eth0
```

The web dashboard will automatically detect new log files and update in real-time.

## Configuration

### Port Configuration
Edit `web_app.py` to change the port:
```python
uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
```

### Update Interval
The dashboard auto-refreshes every 5 seconds. To change:
```javascript
// In the HTML, modify:
setInterval(updateDashboard, 5000);  // Change 5000 to desired milliseconds
```

### Log Monitoring Frequency
Background log monitoring checks every 5 seconds. To adjust:
```python
async def monitor_logs():
    await asyncio.sleep(5)  # Change to desired interval
```

## Troubleshooting

### Port Already in Use
If port 8000 is occupied:
```bash
# Find process using port 8000
lsof -i :8000

# Kill the process
kill -9 <PID>

# Or use a different port
uvicorn web_app:app --port 8080
```

### No Data Displayed
1. Check if log files exist in the `logs/` directory
2. Ensure the model has been trained (`trained_models/unsw_attack_detector.joblib`)
3. Run live detection to generate data:
   ```bash
   sudo python3 live_anomaly_detection.py
   ```

### WebSocket Connection Failed
- Check firewall settings
- Ensure no proxy is blocking WebSocket connections
- Try using HTTP instead of HTTPS for local testing

### Permission Errors
```bash
chmod +x start_web_app.sh
chmod -R 755 logs/ trained_models/ test_results/
```

## Performance Optimization

### For High Traffic Environments

1. **Increase Worker Processes**:
```bash
uvicorn web_app:app --workers 4 --host 0.0.0.0 --port 8000
```

2. **Use Gunicorn with Uvicorn Workers**:
```bash
pip install gunicorn
gunicorn web_app:app -w 4 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000
```

3. **Enable Caching** (for production):
Install Redis and implement caching for frequently accessed data.

### Log Rotation
For long-running deployments, implement log rotation:
```bash
# Add to crontab
0 0 * * * find /path/to/logs -name "*.csv" -mtime +7 -delete
```

## Security Considerations

### Production Deployment

1. **Use HTTPS**: Deploy behind a reverse proxy (Nginx/Apache)
2. **Authentication**: Add authentication middleware
3. **Rate Limiting**: Implement API rate limiting
4. **CORS**: Restrict allowed origins in production

Example Nginx configuration:
```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location /ws {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

## Advanced Features

### Custom Alert Rules
Modify the severity classification in `web_app.py`:
```python
# Adjust confidence thresholds
if confidence >= 0.9:
    stats["severity_distribution"]["high"] += 1
elif confidence >= 0.7:
    stats["severity_distribution"]["medium"] += 1
```

### Export Functionality
Add endpoints to export data:
```python
@app.get("/api/export/anomalies")
async def export_anomalies():
    # Implementation for CSV/JSON export
    pass
```

## Support and Contribution

For issues or feature requests, please check:
- Project documentation
- GitHub repository
- System logs in the terminal

## Additional Resources

- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [Bootstrap 5 Documentation](https://getbootstrap.com/docs/5.3/)
- [Chart.js Documentation](https://www.chartjs.org/)
- [WebSocket Protocol](https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API)
