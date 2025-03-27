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

# Check if running as root
if [ "$UID" -ne 0 ]; then
  error_exit "This script must be run as root. Try 'sudo $0'"
fi

# Define paths
VENV_DIR=".venv"
VENV_ACTIVATE="$VENV_DIR/bin/activate"
SCRIPT="main.py"

# Check if virtual environment exists
if [ ! -d "$VENV_DIR" ]; then
  error_exit "Virtual environment directory '$VENV_DIR' not found. Please create it first."
fi

# Check if activation script exists
if [ ! -f "$VENV_ACTIVATE" ]; then
  error_exit "Virtual environment activation script not found at '$VENV_ACTIVATE'"
fi

# Activate the virtual environment
echo "Activating virtual environment..."
source "$VENV_ACTIVATE" || error_exit "Failed to activate virtual environment"

# Run the main script
echo "Running network enumeration..."
if [ -f "$SCRIPT" ]; then
  python3 "$SCRIPT"
else
  error_exit "Main script '$SCRIPT' not found"
fi

echo "Network enumeration completed successfully"