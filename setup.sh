#!/bin/bash

################################################################################
# BRAMKA AI - Professional Installation Script
# Version: 1.0.0
# Description: Automated setup for production-grade AI penetration testing system
# Author: BRAMKA Team
# License: Educational Use Only
################################################################################

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Banner
print_banner() {
    echo -e "${GREEN}"
    cat << "EOF"
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   🔥 BRAMKA AI - Professional Installation                   ║
║   Autonomous AI-Powered Penetration Testing System           ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

# Check if running on Kali Linux
check_system() {
    log_info "Checking system requirements..."
    
    if [[ ! -f /etc/os-release ]]; then
        log_error "Cannot determine OS. This script is designed for Kali Linux."
        exit 1
    fi
    
    source /etc/os-release
    if [[ "$ID" != "kali" ]]; then
        log_warning "Not running on Kali Linux. Some features may not work."
        read -p "Continue anyway? (y/n): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
    
    log_success "System check passed"
}

# Check Python version
check_python() {
    log_info "Checking Python version..."
    
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 is not installed!"
        exit 1
    fi
    
    PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
    PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d'.' -f1)
    PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d'.' -f2)
    
    if [[ $PYTHON_MAJOR -lt 3 ]] || [[ $PYTHON_MAJOR -eq 3 && $PYTHON_MINOR -lt 9 ]]; then
        log_error "Python 3.9+ required. Found: $PYTHON_VERSION"
        exit 1
    fi
    
    log_success "Python $PYTHON_VERSION detected"
}

# Create project structure
create_structure() {
    log_info "Creating project structure..."
    
    # Main directories
    mkdir -p src/{core,modules,tools,database,utils}
    mkdir -p data/{vector_db,sqlite,logs,reports,downloads}
    mkdir -p config
    mkdir -p dashboard
    mkdir -p tests
    mkdir -p docs
    mkdir -p models/{whisper,piper}
    
    # Create __init__.py files for Python packages
    touch src/__init__.py
    touch src/core/__init__.py
    touch src/modules/__init__.py
    touch src/tools/__init__.py
    touch src/database/__init__.py
    touch src/utils/__init__.py
    
    # Create empty log files
    touch data/logs/bramka.log
    touch data/logs/errors.log
    touch data/logs/attacks.log
    
    log_success "Project structure created"
}

# Install system dependencies
install_system_deps() {
    log_info "Installing system dependencies..."
    
    sudo apt update
    
    # Core dependencies
    PACKAGES=(
        "python3-pip"
        "python3-venv"
        "python3-dev"
        "build-essential"
        "git"
        "curl"
        "wget"
        # Audio/Voice dependencies
        "ffmpeg"
        "portaudio19-dev"
        "libasound2-dev"
        # Database dependencies
        "sqlite3"
        "libsqlite3-dev"
        # Network tools (verify they exist)
        "nmap"
        "sqlmap"
        # Additional utilities
        "jq"
        "tree"
    )
    
    for package in "${PACKAGES[@]}"; do
        if dpkg -l | grep -q "^ii  $package"; then
            log_success "$package already installed"
        else
            log_info "Installing $package..."
            sudo apt install -y "$package" || log_warning "Failed to install $package"
        fi
    done
    
    log_success "System dependencies installed"
}

# Create and activate virtual environment
setup_venv() {
    log_info "Setting up Python virtual environment..."
    
    if [[ -d "venv" ]]; then
        log_warning "Virtual environment already exists"
        read -p "Recreate? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            rm -rf venv
            python3 -m venv venv
        fi
    else
        python3 -m venv venv
    fi
    
    source venv/bin/activate
    
    # Upgrade pip
    log_info "Upgrading pip..."
    pip install --upgrade pip setuptools wheel
    
    log_success "Virtual environment ready"
}

# Install Python dependencies
install_python_deps() {
    log_info "Installing Python dependencies..."
    
    if [[ ! -f "requirements.txt" ]]; then
        log_error "requirements.txt not found!"
        exit 1
    fi
    
    source venv/bin/activate
    
    # Install with progress
    pip install -r requirements.txt --no-cache-dir
    
    log_success "Python dependencies installed"
}

# Download AI models
download_models() {
    log_info "Downloading AI models..."
    
    # Whisper model (for voice recognition)
    log_info "Downloading Whisper model (base)..."
    mkdir -p models/whisper
    # Model will be auto-downloaded on first use
    
    # Piper TTS model
    log_info "Downloading Piper TTS model..."
    mkdir -p models/piper
    # Model will be auto-downloaded on first use
    
    log_success "AI models prepared"
}

# Setup configuration files
setup_config() {
    log_info "Setting up configuration..."
    
    # Create .env from example if not exists
    if [[ ! -f ".env" ]]; then
        if [[ -f ".env.example" ]]; then
            cp .env.example .env
            log_success ".env file created from template"
            log_warning "Please edit .env and add your API keys!"
        else
            log_warning ".env.example not found. Skipping .env creation."
        fi
    else
        log_success ".env already exists"
    fi
    
    # Set permissions
    chmod 600 .env 2>/dev/null || true
    chmod +x main.py 2>/dev/null || true
}

# Initialize databases
init_databases() {
    log_info "Initializing databases..."
    
    # SQLite database will be created automatically on first run
    mkdir -p data/sqlite
    
    # ChromaDB directory
    mkdir -p data/vector_db
    
    log_success "Database directories ready"
}

# Verify installation
verify_installation() {
    log_info "Verifying installation..."
    
    source venv/bin/activate
    
    # Check critical imports
    python3 << 'EOF'
import sys

packages = [
    'groq',
    'chromadb',
    'fastapi',
    'streamlit',
    'faster_whisper',
    'pydantic',
    'pyyaml',
    'requests'
]

missing = []
for pkg in packages:
    try:
        __import__(pkg)
    except ImportError:
        missing.append(pkg)

if missing:
    print(f"❌ Missing packages: {', '.join(missing)}")
    sys.exit(1)
else:
    print("✅ All critical packages installed")
EOF
    
    if [[ $? -eq 0 ]]; then
        log_success "Installation verified successfully"
    else
        log_error "Installation verification failed"
        exit 1
    fi
}

# Print next steps
print_next_steps() {
    echo -e "\n${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                                                               ║${NC}"
    echo -e "${GREEN}║   ✅ BRAMKA AI Installation Complete!                        ║${NC}"
    echo -e "${GREEN}║                                                               ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}\n"
    
    echo -e "${BLUE}Next Steps:${NC}\n"
    echo "1. Activate virtual environment:"
    echo -e "   ${YELLOW}source venv/bin/activate${NC}\n"
    
    echo "2. Configure your API keys:"
    echo -e "   ${YELLOW}nano .env${NC}"
    echo "   Add your Groq API key (get free at: https://console.groq.com)\n"
    
    echo "3. Run BRAMKA AI:"
    echo -e "   ${YELLOW}python3 main.py${NC}\n"
    
    echo "4. Or start the dashboard:"
    echo -e "   ${YELLOW}streamlit run dashboard/app.py${NC}\n"
    
    echo -e "${BLUE}Documentation:${NC}"
    echo -e "   ${YELLOW}docs/INSTALLATION.md${NC} - Detailed setup guide"
    echo -e "   ${YELLOW}docs/USAGE.md${NC} - How to use BRAMKA AI"
    echo -e "   ${YELLOW}README.md${NC} - Project overview\n"
    
    echo -e "${RED}⚠️  Important:${NC}"
    echo "   - Use ONLY on authorized systems"
    echo "   - Educational purposes only"
    echo "   - Follow ethical hacking guidelines\n"
}

# Main installation flow
main() {
    print_banner
    
    check_system
    check_python
    create_structure
    install_system_deps
    setup_venv
    install_python_deps
    download_models
    setup_config
    init_databases
    verify_installation
    
    print_next_steps
}

# Run main function
main

log_success "Setup complete! 🚀"
