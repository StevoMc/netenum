#!/bin/bash
#
# netenum.sh - Network enumeration script
# Run this script as root to perform network enumeration tasks

# Exit on error
set -e

# Function to print error messages
error_exit() {
  echo "ERROR: $1" >&2
  exit 1
}

# Function to print info messages
info() {
  echo "[+] $1"
}

# Check if running as root
if [ "$UID" -ne 0 ]; then
  error_exit "This script must be run as root. Try 'sudo $0'"
fi

# Define paths
VENV_DIR=".venv"
VENV_ACTIVATE="$VENV_DIR/bin/activate"
SCRIPT="main.py"
REQUIREMENTS="requirements.txt"

# Check for dependencies
info "Checking dependencies..."

# Check for Nmap
if ! command -v nmap &> /dev/null; then
  info "Nmap not found. Installing..."
  apt update
  apt install -y nmap || error_exit "Failed to install Nmap"
fi

# Check for Chromium
if ! command -v chromium-browser &> /dev/null && ! command -v chromium &> /dev/null; then
  info "Chromium not found. Installing..."
  apt update
  apt install -y chromium-browser || error_exit "Failed to install Chromium"
fi

# Create virtual environment if it doesn't exist
if [ ! -d "$VENV_DIR" ]; then
  info "Creating virtual environment..."
  python3 -m venv "$VENV_DIR" || error_exit "Failed to create virtual environment"
fi

# Activate the virtual environment
info "Activating virtual environment..."
source "$VENV_ACTIVATE" || error_exit "Failed to activate virtual environment"

# Install requirements if requirements.txt exists
if [ -f "$REQUIREMENTS" ]; then
  info "Installing Python dependencies..."
  pip install -r "$REQUIREMENTS" || error_exit "Failed to install requirements"
fi

# Run the main script
info "Running network enumeration..."
if [ -f "$SCRIPT" ]; then
  python3 "$SCRIPT"
else
  error_exit "Main script '$SCRIPT' not found"
fi

info "Network enumeration completed successfully"