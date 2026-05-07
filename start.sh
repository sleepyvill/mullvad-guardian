#!/bin/bash

# Mullvad Guardian Web UI Launcher

echo "🛡️  Mullvad Guardian Web UI"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed. Please install Python 3.10 or higher."
    exit 1
fi

# Check Python version
PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
REQUIRED_VERSION="3.10"

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    echo "❌ Python $PYTHON_VERSION detected. Python 3.10 or higher is required."
    exit 1
fi

# Check if requests is installed
if ! python3 -c "import requests" &> /dev/null; then
    echo "⚠️  'requests' module not found. Installing..."
    pip install requests
fi

# Check if Mullvad CLI is available
if ! command -v mullvad &> /dev/null; then
    echo "⚠️  Mullvad CLI not found. Please install Mullvad VPN."
    echo "   Download: https://mullvad.net/download"
    echo ""
fi

# Start the server
echo "🚀 Starting web server..."
echo ""
python3 server.py
