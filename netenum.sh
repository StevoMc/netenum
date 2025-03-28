#!/usr/bin/env bash
#
# netenum.sh - Network enumeration script
# Run this script as root to perform network enumeration tasks

# Strict mode
set -o errexit  # Exit on error
set -o pipefail # Exit on pipe failures
set -o nounset  # Exit on undefined variables

# Constants
readonly SCRIPT_NAME=$(basename "${0}")
readonly SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
readonly VENV_DIR="${SCRIPT_DIR}/.venv"
readonly VENV_ACTIVATE="${VENV_DIR}/bin/activate"
readonly SCRIPT="main.py"
readonly REQUIREMENTS="requirements.txt"
readonly LOG_FILE="${SCRIPT_DIR}/netenum_$(date +%Y%m%d_%H%M%S).log"

# Terminal colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[0;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Log levels
log_error() { echo -e "${RED}[ERROR] $(date '+%Y-%m-%d %H:%M:%S')${NC} - $*" | tee -a "${LOG_FILE}" >&2; }
log_warn() { echo -e "${YELLOW}[WARN]  $(date '+%Y-%m-%d %H:%M:%S')${NC} - $*" | tee -a "${LOG_FILE}"; }
log_info() { echo -e "${GREEN}[INFO]  $(date '+%Y-%m-%d %H:%M:%S')${NC} - $*" | tee -a "${LOG_FILE}"; }
log_debug() { echo -e "${BLUE}[DEBUG] $(date '+%Y-%m-%d %H:%M:%S')${NC} - $*" | tee -a "${LOG_FILE}"; }

# Error handling
error_exit() {
  log_error "$1"
  exit 1
}

# Cleanup function
cleanup() {
  log_debug "Performing cleanup..."
  # Remove old netenum log files
  find "${SCRIPT_DIR}" -name 'netenum_*.log' -type f -delete
  find "/tmp/runtime-root" -type d -delete
  log_info "Cleanup completed"
  log_info "Exiting script"
  exit 0
}

# Signal handlers
handle_signal() {
  local signal=$1
  log_warn "Received signal: ${signal}"
  exit 1
}

# Register signal handlers
trap 'handle_signal SIGINT' INT
trap 'handle_signal SIGTERM' TERM
trap 'handle_signal SIGHUP' HUP
trap cleanup EXIT

# Display banner
show_banner() {
  cat <<'EOF'

    _   _          _     _____                             
   | \ | |   ___  | |_  | ____|  _ __    _   _   _ __ ___  
   |  \| |  / _ \ | __| |  _|   | '_ \  | | | | | '_ ` _ \ 
   | |\  | |  __/ | |_  | |___  | | | | | |_| | | | | | | |
   |_| \_|  \___|  \__| |_____| |_| |_|  \__,_| |_| |_| |_|
                                                           

EOF
  log_info "Network Enumeration Tool v1.0"
  log_info "Starting execution at $(date)"
  log_info "Logging to ${LOG_FILE}"
}

# Check if command exists
command_exists() {
  command -v "$1" &>/dev/null
}

# Install package if missing
install_package() {
  local package=$1

  if ! command_exists "${package}"; then
    log_info "${package} not found. Installing..."

    # Check package manager
    if command_exists apt-get; then
      apt-get update -qq && apt-get install -y "${package}" || error_exit "Failed to install ${package}"
    elif command_exists dnf; then
      dnf install -y "${package}" || error_exit "Failed to install ${package}"
    elif command_exists yum; then
      yum install -y "${package}" || error_exit "Failed to install ${package}"
    else
      error_exit "No supported package manager found. Please install ${package} manually."
    fi
  else
    log_debug "${package} is already installed"
  fi
}

# Check dependencies
check_dependencies() {
  log_info "Checking dependencies..."

  # Check for Python 3
  if ! command_exists python3; then
    error_exit "Python 3 is required but not installed"
  fi

  # Check for pip
  if ! command_exists pip3; then
    install_package "python3-pip"
  fi

  # Check for venv module
  if ! python3 -c "import venv" &>/dev/null; then
    install_package "python3-venv"
  fi

  # Check for Nmap
  install_package "nmap"

  # Check for Chromium
  if ! command_exists chromium-browser && ! command_exists chromium; then
    if command_exists apt-get; then
      install_package "chromium-browser"
    else
      install_package "chromium"
    fi
  fi
}

# Setup virtual environment
setup_venv() {
  log_info "Setting up virtual environment..."

  if [[ ! -d "${VENV_DIR}" ]]; then
    log_info "Creating virtual environment..."
    python3 -m venv "${VENV_DIR}" || error_exit "Failed to create virtual environment"
  fi

  log_info "Activating virtual environment..."
  # shellcheck disable=SC1090
  source "${VENV_ACTIVATE}" || error_exit "Failed to activate virtual environment"

  if [[ -f "${REQUIREMENTS}" ]]; then
    log_info "Installing Python dependencies..."
    python3 -m pip install --upgrade pip
    python3 -m pip install -r "${REQUIREMENTS}" || error_exit "Failed to install requirements"
  else
    log_warn "Requirements file not found: ${REQUIREMENTS}"
  fi
}

# Main execution
main() {
  # Check if running as root
  if [[ $EUID -ne 0 ]]; then
    error_exit "This script must be run as root. Try 'sudo ${SCRIPT_NAME}'"
  fi

  # Show banner
  show_banner

  # Check dependencies
  check_dependencies

  # Setup virtual environment
  setup_venv

  # Run the main script
  log_info "Running network enumeration..."
  if [[ -f "${SCRIPT}" ]]; then
    python3 "${SCRIPT}"
  else
    error_exit "Main script '${SCRIPT}' not found"
  fi

  log_info "Network enumeration completed successfully"
}

# Run main function
main "$@"
