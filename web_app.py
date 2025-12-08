#!/usr/bin/env python3
"""
Web-based GUI for Network Anomaly Detection System
==================================================

FastAPI-based web interface for monitoring network anomalies in real-time.
Provides real-time alerts, logs visualization, and system statistics.

Usage:
    python3 web_app.py
    Then open http://localhost:8000 in your browser
"""
import json
import os
import glob
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Optional
import asyncio

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import pandas as pd
import uvicorn

# Initialize FastAPI app
app = FastAPI(
    title="Network Anomaly Detection System",
    description="Real-time network intrusion detection and monitoring",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuration
LOGS_DIR = Path("logs")
MODELS_DIR = Path("trained_models")
TEST_RESULTS_DIR = Path("test_results")

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except:
                pass

manager = ConnectionManager()


# Helper functions
def get_latest_files(directory: Path, pattern: str) -> List[Path]:
    """Get latest files matching pattern sorted by modification time."""
    files = list(directory.glob(pattern))
    return sorted(files, key=lambda x: x.stat().st_mtime, reverse=True)


def load_anomalies_json(file_path: Path) -> List[Dict]:
    """Load anomalies from JSON file."""
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except Exception as e:
        print(f"Error loading {file_path}: {e}")
        return []


def load_anomalies_csv(file_path: Path, limit: int = 100) -> List[Dict]:
    """Load anomalies from CSV file."""
    try:
        df = pd.read_csv(file_path)
        df = df.head(limit)
        return df.to_dict('records')
    except Exception as e:
        print(f"Error loading {file_path}: {e}")
        return []


def load_flows_csv(file_path: Path, limit: int = 100) -> List[Dict]:
    """Load network flows from CSV file."""
    try:
        df = pd.read_csv(file_path)
        df = df.head(limit)
        return df.to_dict('records')
    except Exception as e:
        print(f"Error loading {file_path}: {e}")
        return []


def get_model_info() -> Dict:
    """Get information about the trained model."""
    try:
        report_file = MODELS_DIR / "unsw_training_report.json"
        if report_file.exists():
            with open(report_file, 'r') as f:
                return json.load(f)
    except Exception as e:
        print(f"Error loading model info: {e}")
    return {}


def get_test_results() -> Dict:
    """Get test results."""
    try:
        report_file = TEST_RESULTS_DIR / "test_report.json"
        if report_file.exists():
            with open(report_file, 'r') as f:
                return json.load(f)
    except Exception as e:
        print(f"Error loading test results: {e}")
    return {}


def get_statistics() -> Dict:
    """Calculate real-time statistics from logs."""
    stats = {
        "total_anomalies": 0,
        "total_flows": 0,
        "attack_types": {},
        "recent_anomalies": 0,
        "severity_distribution": {"high": 0, "medium": 0, "low": 0}
    }
    
    try:
        # Get latest anomalies file
        anomaly_files = get_latest_files(LOGS_DIR, "anomalies_*.json")
        if anomaly_files:
            anomalies = load_anomalies_json(anomaly_files[0])
            stats["total_anomalies"] = len(anomalies)
            
            # Count attack types
            for anomaly in anomalies:
                attack_type = anomaly.get("predicted_attack", "Unknown")
                stats["attack_types"][attack_type] = stats["attack_types"].get(attack_type, 0) + 1
                
                # Calculate recent anomalies (last 5 minutes)
                timestamp = anomaly.get("timestamp", "")
                # Increment recent count (simplified)
                
            # Assign severity based on confidence
            for anomaly in anomalies:
                confidence = anomaly.get("confidence", 0.5)
                if confidence >= 0.9:
                    stats["severity_distribution"]["high"] += 1
                elif confidence >= 0.7:
                    stats["severity_distribution"]["medium"] += 1
                else:
                    stats["severity_distribution"]["low"] += 1
        
        # Get latest flows file
        flow_files = get_latest_files(LOGS_DIR, "flows_*.csv")
        if flow_files:
            df = pd.read_csv(flow_files[0])
            stats["total_flows"] = len(df)
            
    except Exception as e:
        print(f"Error calculating statistics: {e}")
    
    return stats


# API Routes

@app.get("/", response_class=HTMLResponse)
async def read_root():
    """Serve the main HTML page."""
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Network Anomaly Detection System</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
        <link href="https://fonts.googleapis.com/css2?family=Oswald:wght@400;600;700&display=swap" rel="stylesheet">
        <style>
            body {
                background: #ffffff;
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                min-height: 100vh;
                margin: 0;
                padding: 0;
            }
            .dashboard-container {
                padding: 0;
            }
            .card {
                border-radius: 0;
                box-shadow: none;
                border: 2px solid #000000;
                margin-bottom: 0;
                margin-top: 0;
                background: #ffffff;
            }
            .card-header {
                border-radius: 0 !important;
                border-bottom: 2px solid #000000 !important;
            }
            .stat-card {
                background: #ffffff;
                color: #000000;
                padding: 20px;
                border-radius: 0;
                border: 2px solid #000000;
                text-align: center;
                margin-bottom: 0;
            }
            .stat-card h3 {
                font-size: 2.5rem;
                font-weight: bold;
                margin: 10px 0;
                color: #000000;
            }
            .stat-card p {
                margin: 0;
                color: #000000;
            }
            .alert-item {
                border-left: 4px solid #dc3545;
                padding: 10px;
                margin-bottom: 10px;
                background: #fff;
                border-radius: 0;
                border: 1px solid #000000;
            }
            .alert-high { border-left-color: #dc3545; }
            .alert-medium { border-left-color: #ffc107; }
            .alert-low { border-left-color: #28a745; }
            .table-container {
                max-height: 400px;
                overflow-y: auto;
            }
            .header-section {
                background: #0C4B33;
                padding: 20px;
                border-radius: 0;
                margin: 0;
                box-shadow: none;
                border-bottom: 3px solid #000000;
            }
            .header-section h1 {
                font-family: 'Oswald', sans-serif;
                font-weight: 700;
                color: #ffffff !important;
                letter-spacing: 1px;
            }
            .header-section p,
            .header-section strong,
            .header-section span {
                color: #ffffff !important;
            }
            .text-muted {
                color: #cccccc !important;
            }
            .status-indicator {
                display: inline-block;
                width: 12px;
                height: 12px;
                border-radius: 50%;
                margin-right: 8px;
                animation: pulse 2s infinite;
            }
            .status-active { background-color: #28a745; }
            .status-warning { background-color: #ffc107; }
            .status-danger { background-color: #dc3545; }
            @keyframes pulse {
                0%, 100% { opacity: 1; }
                50% { opacity: 0.5; }
            }
            .chart-container {
                height: 300px;
                padding: 20px;
            }
            .log-entry {
                font-family: 'Courier New', monospace;
                font-size: 0.9rem;
                padding: 5px;
                border-bottom: 1px solid #000000;
            }
            .table {
                color: #000000;
            }
            .table-striped tbody tr:nth-of-type(odd) {
                background-color: #f8f9fa;
            }
            .badge {
                border-radius: 0;
            }
            .btn {
                border-radius: 0;
            }
            .card-body {
                color: #000000;
            }
            .row {
                margin-left: 0;
                margin-right: 0;
            }
            .col-md-3, .col-md-6, .col-md-12 {
                padding-left: 0;
                padding-right: 0;
            }
        </style>
    </head>
    <body>
        <div class="dashboard-container">
            <!-- Header -->
            <div class="header-section">
                <div class="d-flex justify-content-between align-items-center">
                    <div>
                        <h1><i class="fas fa-shield-alt"></i> Network Anomaly Detection System</h1>
                        <p class="text-muted mb-0">Real-time Network Intrusion Detection and Monitoring</p>
                    </div>
                    <div class="text-end">
                        <div>
                            <span class="status-indicator status-active"></span>
                            <strong>System Status: </strong><span id="system-status">Active</span>
                        </div>
                        <div class="mt-2">
                            <small class="text-muted">Last Updated: <span id="last-update">--</span></small>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Statistics Cards -->
            <div class="row">
                <div class="col-md-3">
                    <div class="stat-card">
                        <i class="fas fa-exclamation-triangle fa-2x"></i>
                        <h3 id="total-anomalies">0</h3>
                        <p>Total Anomalies Detected</p>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stat-card">
                        <i class="fas fa-network-wired fa-2x"></i>
                        <h3 id="total-flows">0</h3>
                        <p>Network Flows Analyzed</p>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stat-card">
                        <i class="fas fa-bug fa-2x"></i>
                        <h3 id="attack-types">0</h3>
                        <p>Attack Types Identified</p>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stat-card">
                        <i class="fas fa-chart-line fa-2x"></i>
                        <h3 id="model-accuracy">--</h3>
                        <p>Model Accuracy</p>
                    </div>
                </div>
            </div>

            <!-- Main Content -->
            <div class="row">
                <!-- Recent Alerts -->
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-header" style="background-color: #0C4B33; color: #ffffff; border-bottom: 2px solid #000000;">
                            <h5 class="mb-0"><i class="fas fa-bell"></i> Recent Alerts</h5>
                        </div>
                        <div class="card-body table-container" id="alerts-container">
                            <div class="text-center text-muted">
                                <i class="fas fa-spinner fa-spin"></i> Loading alerts...
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Attack Distribution -->
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-header" style="background-color: #0C4B33; color: #ffffff; border-bottom: 2px solid #000000;">
                            <h5 class="mb-0"><i class="fas fa-chart-pie"></i> Attack Type Distribution</h5>
                        </div>
                        <div class="card-body">
                            <div id="attack-distribution">
                                <div class="text-center text-muted">
                                    <i class="fas fa-spinner fa-spin"></i> Loading data...
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Network Flows and Logs -->
            <div class="row">
                <div class="col-md-12">
                    <div class="card">
                        <div class="card-header" style="background-color: #0C4B33; color: #ffffff; border-bottom: 2px solid #000000;">
                            <h5 class="mb-0"><i class="fas fa-stream"></i> Recent Network Flows</h5>
                        </div>
                        <div class="card-body table-container">
                            <div class="table-responsive">
                                <table class="table table-striped table-hover" id="flows-table">
                                    <thead>
                                        <tr>
                                            <th>Timestamp</th>
                                            <th>Source IP</th>
                                            <th>Dest IP</th>
                                            <th>Protocol</th>
                                            <th>Packets</th>
                                            <th>Bytes</th>
                                            <th>Status</th>
                                        </tr>
                                    </thead>
                                    <tbody id="flows-tbody">
                                        <tr>
                                            <td colspan="7" class="text-center text-muted">
                                                <i class="fas fa-spinner fa-spin"></i> Loading flows...
                                            </td>
                                        </tr>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Model Information -->
            <div class="row">
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-header" style="background-color: #0C4B33; color: #ffffff; border-bottom: 2px solid #000000;">
                            <h5 class="mb-0"><i class="fas fa-brain"></i> Model Information</h5>
                        </div>
                        <div class="card-body" id="model-info">
                            <div class="text-center text-muted">
                                <i class="fas fa-spinner fa-spin"></i> Loading model info...
                            </div>
                        </div>
                    </div>
                </div>

                <!-- System Logs -->
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-header" style="background-color: #0C4B33; color: #ffffff; border-bottom: 2px solid #000000;">
                            <h5 class="mb-0"><i class="fas fa-file-alt"></i> System Logs</h5>
                        </div>
                        <div class="card-body table-container" id="system-logs">
                            <div class="text-center text-muted">
                                <i class="fas fa-spinner fa-spin"></i> Monitoring system...
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
        <script>
            let ws = null;
            let attackChart = null;

            // Initialize WebSocket connection
            function connectWebSocket() {
                const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
                ws = new WebSocket(`${protocol}//${window.location.host}/ws`);
                
                ws.onopen = () => {
                    console.log('WebSocket connected');
                    document.getElementById('system-status').textContent = 'Active';
                };
                
                ws.onmessage = (event) => {
                    const data = JSON.parse(event.data);
                    if (data.type === 'update') {
                        updateDashboard();
                    }
                };
                
                ws.onerror = (error) => {
                    console.error('WebSocket error:', error);
                    document.getElementById('system-status').textContent = 'Error';
                };
                
                ws.onclose = () => {
                    console.log('WebSocket disconnected. Reconnecting...');
                    document.getElementById('system-status').textContent = 'Reconnecting...';
                    setTimeout(connectWebSocket, 3000);
                };
            }

            // Update dashboard with latest data
            async function updateDashboard() {
                updateLastUpdateTime();
                await Promise.all([
                    updateStatistics(),
                    updateAlerts(),
                    updateFlows(),
                    updateModelInfo()
                ]);
            }

            // Update statistics
            async function updateStatistics() {
                try {
                    const response = await fetch('/api/statistics');
                    const stats = await response.json();
                    
                    document.getElementById('total-anomalies').textContent = stats.total_anomalies || 0;
                    document.getElementById('total-flows').textContent = stats.total_flows || 0;
                    document.getElementById('attack-types').textContent = Object.keys(stats.attack_types || {}).length;
                    
                    updateAttackDistribution(stats.attack_types || {});
                } catch (error) {
                    console.error('Error updating statistics:', error);
                }
            }

            // Update alerts display
            async function updateAlerts() {
                try {
                    const response = await fetch('/api/anomalies/latest?limit=10');
                    const anomalies = await response.json();
                    
                    const container = document.getElementById('alerts-container');
                    if (anomalies.length === 0) {
                        container.innerHTML = '<div class="text-center text-muted">No anomalies detected</div>';
                        return;
                    }
                    
                    container.innerHTML = anomalies.map(anomaly => {
                        const confidence = anomaly.confidence || 0.5;
                        const severity = confidence >= 0.9 ? 'high' : confidence >= 0.7 ? 'medium' : 'low';
                        return `
                            <div class="alert-item alert-${severity}">
                                <strong>${anomaly.predicted_attack || 'Unknown'}</strong>
                                <span class="badge bg-${severity === 'high' ? 'danger' : severity === 'medium' ? 'warning' : 'success'} float-end">
                                    ${(confidence * 100).toFixed(1)}%
                                </span>
                                <div class="small text-muted">
                                    ${anomaly.src_ip || 'N/A'} → ${anomaly.dst_ip || 'N/A'} | 
                                    ${anomaly.timestamp || 'N/A'}
                                </div>
                            </div>
                        `;
                    }).join('');
                } catch (error) {
                    console.error('Error updating alerts:', error);
                }
            }

            // Update flows table
            async function updateFlows() {
                try {
                    const response = await fetch('/api/flows/latest?limit=20');
                    const flows = await response.json();
                    
                    const tbody = document.getElementById('flows-tbody');
                    if (flows.length === 0) {
                        tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted">No flows recorded</td></tr>';
                        return;
                    }
                    
                    tbody.innerHTML = flows.map(flow => `
                        <tr>
                            <td>${flow.timestamp || 'N/A'}</td>
                            <td>${flow.src_ip || 'N/A'}</td>
                            <td>${flow.dst_ip || 'N/A'}</td>
                            <td>${flow.protocol || 'N/A'}</td>
                            <td>${flow.packets || 0}</td>
                            <td>${flow.bytes || 0}</td>
                            <td><span class="badge bg-${flow.is_anomaly ? 'danger' : 'success'}">${flow.is_anomaly ? 'Anomaly' : 'Normal'}</span></td>
                        </tr>
                    `).join('');
                } catch (error) {
                    console.error('Error updating flows:', error);
                }
            }

            // Update model information
            async function updateModelInfo() {
                try {
                    const response = await fetch('/api/model/info');
                    const modelInfo = await response.json();
                    
                    if (modelInfo.accuracy) {
                        document.getElementById('model-accuracy').textContent = 
                            (modelInfo.accuracy * 100).toFixed(1) + '%';
                    }
                    
                    const container = document.getElementById('model-info');
                    container.innerHTML = `
                        <div class="row">
                            <div class="col-6">
                                <p><strong>Model Type:</strong> ${modelInfo.model_type || 'N/A'}</p>
                                <p><strong>Accuracy:</strong> ${modelInfo.accuracy ? (modelInfo.accuracy * 100).toFixed(2) + '%' : 'N/A'}</p>
                                <p><strong>Precision:</strong> ${modelInfo.precision ? (modelInfo.precision * 100).toFixed(2) + '%' : 'N/A'}</p>
                            </div>
                            <div class="col-6">
                                <p><strong>Recall:</strong> ${modelInfo.recall ? (modelInfo.recall * 100).toFixed(2) + '%' : 'N/A'}</p>
                                <p><strong>F1-Score:</strong> ${modelInfo.f1_score ? (modelInfo.f1_score * 100).toFixed(2) + '%' : 'N/A'}</p>
                                <p><strong>Training Date:</strong> ${modelInfo.training_date || 'N/A'}</p>
                            </div>
                        </div>
                    `;
                } catch (error) {
                    console.error('Error updating model info:', error);
                }
            }

            // Update attack distribution chart
            function updateAttackDistribution(attackTypes) {
                const ctx = document.getElementById('attack-distribution');
                
                if (Object.keys(attackTypes).length === 0) {
                    ctx.innerHTML = '<div class="text-center text-muted">No attack data available</div>';
                    return;
                }
                
                // Clear previous content and create canvas
                ctx.innerHTML = '<canvas id="attack-chart"></canvas>';
                const canvas = document.getElementById('attack-chart');
                
                if (attackChart) {
                    attackChart.destroy();
                }
                
                attackChart = new Chart(canvas, {
                    type: 'doughnut',
                    data: {
                        labels: Object.keys(attackTypes),
                        datasets: [{
                            data: Object.values(attackTypes),
                            backgroundColor: [
                                '#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF',
                                '#FF9F40', '#FF6384', '#C9CBCF', '#4BC0C0', '#FF6384'
                            ]
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: {
                                position: 'right'
                            }
                        }
                    }
                });
            }

            // Update last update time
            function updateLastUpdateTime() {
                const now = new Date();
                document.getElementById('last-update').textContent = now.toLocaleTimeString();
            }

            // Initialize dashboard
            document.addEventListener('DOMContentLoaded', () => {
                connectWebSocket();
                updateDashboard();
                
                // Auto-refresh every 5 seconds
                setInterval(updateDashboard, 5000);
            });
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)


@app.get("/api/statistics")
async def get_statistics_api():
    """Get real-time statistics."""
    return JSONResponse(get_statistics())


@app.get("/api/anomalies/latest")
async def get_latest_anomalies(limit: int = 50):
    """Get latest anomalies."""
    try:
        anomaly_files = get_latest_files(LOGS_DIR, "anomalies_*.json")
        if not anomaly_files:
            return JSONResponse([])
        
        anomalies = load_anomalies_json(anomaly_files[0])
        return JSONResponse(anomalies[:limit])
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/flows/latest")
async def get_latest_flows(limit: int = 100):
    """Get latest network flows."""
    try:
        flow_files = get_latest_files(LOGS_DIR, "flows_*.csv")
        if not flow_files:
            return JSONResponse([])
        
        flows = load_flows_csv(flow_files[0], limit)
        return JSONResponse(flows)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/model/info")
async def get_model_info_api():
    """Get model information."""
    return JSONResponse(get_model_info())


@app.get("/api/test/results")
async def get_test_results_api():
    """Get test results."""
    return JSONResponse(get_test_results())


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time updates."""
    await manager.connect(websocket)
    try:
        while True:
            # Wait for messages (keep connection alive)
            data = await websocket.receive_text()
            # Echo back or handle commands if needed
    except WebSocketDisconnect:
        manager.disconnect(websocket)


# Background task to monitor for new anomalies
async def monitor_logs():
    """Background task to monitor log files and broadcast updates."""
    last_check = datetime.now()
    
    while True:
        await asyncio.sleep(5)  # Check every 5 seconds
        
        try:
            # Check if there are new anomaly files
            anomaly_files = get_latest_files(LOGS_DIR, "anomalies_*.json")
            if anomaly_files:
                latest_file = anomaly_files[0]
                file_mtime = datetime.fromtimestamp(latest_file.stat().st_mtime)
                
                if file_mtime > last_check:
                    # New data detected, broadcast update
                    await manager.broadcast({"type": "update", "timestamp": datetime.now().isoformat()})
                    last_check = datetime.now()
        except Exception as e:
            print(f"Error in monitor_logs: {e}")


@app.on_event("startup")
async def startup_event():
    """Start background tasks on startup."""
    asyncio.create_task(monitor_logs())


if __name__ == "__main__":
    print("=" * 60)
    print("Network Anomaly Detection - Web Interface")
    print("=" * 60)
    print(f"Starting server on http://localhost:8000")
    print(f"Logs directory: {LOGS_DIR.absolute()}")
    print(f"Models directory: {MODELS_DIR.absolute()}")
    print("=" * 60)
    
    # Create directories if they don't exist
    LOGS_DIR.mkdir(exist_ok=True)
    MODELS_DIR.mkdir(exist_ok=True)
    TEST_RESULTS_DIR.mkdir(exist_ok=True)
    
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
