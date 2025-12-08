#!/bin/bash
# Startup script for Network Anomaly Detection Web Application

echo "========================================"
echo "Network Anomaly Detection Web Interface"
echo "========================================"
echo ""

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 is not installed"
    exit 1
fi

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Install/upgrade dependencies
echo "Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Create necessary directories
mkdir -p logs trained_models test_results

echo ""
echo "========================================"
echo "Starting Web Application..."
echo "========================================"
echo "Access the dashboard at: http://localhost:8000"
echo "Press Ctrl+C to stop the server"
echo "========================================"
echo ""

# Start the web application
python3 web_app.py
