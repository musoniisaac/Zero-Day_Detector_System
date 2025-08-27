#!/bin/bash
# Zero-Day Detector Installation Script for Linux
# Supports Ubuntu/Debian and CentOS/RHEL systems
# Created by Isaac Musoni

set -e

# Configuration
ZDD_VERSION="2.1.0"
ZDD_USER="zdd-detector"
ZDD_GROUP="zdd-detector"
INSTALL_DIR="/usr/local/lib/zdd"
BIN_DIR="/usr/local/bin"
CONFIG_DIR="/etc/zdd"
DATA_DIR="/var/lib/zdd"
LOG_DIR="/var/log/zdd"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_debug() {
    echo -e "${BLUE}[DEBUG]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

# Detect Linux distribution
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        VERSION=$VERSION_ID
    else
        log_error "Cannot detect Linux distribution"
        exit 1
    fi
    
    log_info "Detected distribution: $DISTRO $VERSION"
}

# Install system dependencies
install_dependencies() {
    log_info "Installing system dependencies..."
    
    case $DISTRO in
        ubuntu|debian)
            apt update
            apt install -y python3 python3-pip python3-dev python3-venv \
                          libpcap-dev build-essential pkg-config \
                          systemd curl wget
            ;;
        centos|rhel|fedora)
            if command -v dnf &> /dev/null; then
                dnf install -y python3 python3-pip python3-devel \
                              libpcap-devel gcc gcc-c++ pkgconfig \
                              systemd curl wget
            else
                yum install -y python3 python3-pip python3-devel \
                              libpcap-devel gcc gcc-c++ pkgconfig \
                              systemd curl wget
            fi
            ;;
        *)
            log_error "Unsupported distribution: $DISTRO"
            exit 1
            ;;
    esac
}

# Create system user
create_user() {
    log_info "Creating system user: $ZDD_USER"
    
    if ! id "$ZDD_USER" &>/dev/null; then
        useradd -r -s /bin/false -d /var/lib/zdd -c "Zero-Day Detector" $ZDD_USER
        log_info "User $ZDD_USER created"
    else
        log_info "User $ZDD_USER already exists"
    fi
}

# Create directories
create_directories() {
    log_info "Creating directories..."
    
    mkdir -p $INSTALL_DIR
    mkdir -p $CONFIG_DIR/{rules,thresholds,integrations}
    mkdir -p $DATA_DIR/{baselines,logs,cache,databases}
    mkdir -p $LOG_DIR
    
    # Set ownership
    chown -R $ZDD_USER:$ZDD_GROUP $CONFIG_DIR $DATA_DIR $LOG_DIR
    chmod 755 $CONFIG_DIR $DATA_DIR $LOG_DIR
    chmod 644 $CONFIG_DIR/*.yaml 2>/dev/null || true
}

# Install Python dependencies
install_python_deps() {
    log_info "Installing Python dependencies..."
    
    # Create virtual environment
    python3 -m venv $INSTALL_DIR/venv
    source $INSTALL_DIR/venv/bin/activate
    
    # Upgrade pip
    pip install --upgrade pip
    
    # Install requirements
    if [ -f "requirements.txt" ]; then
        pip install -r requirements.txt
    else
        # Install dependencies directly
        pip install psutil watchdog scapy pypcap PyYAML numpy colorlog python-daemon ujson
    fi
    
    deactivate
}

# Install ZDD files
install_zdd_files() {
    log_info "Installing Zero-Day Detector files..."
    
    # Copy source files
    cp -r src/* $INSTALL_DIR/
    
    # Copy configuration
    if [ -f "config/default.yaml" ]; then
        cp config/default.yaml $CONFIG_DIR/config.yaml
    fi
    
    # Create main executable
    cat > $BIN_DIR/zdd-detector << 'EOF'
#!/bin/bash
# Zero-Day Detector main executable

ZDD_DIR="/usr/local/lib/zdd"
source $ZDD_DIR/venv/bin/activate
exec python3 $ZDD_DIR/main.py "$@"
EOF
    
    chmod +x $BIN_DIR/zdd-detector
    
    # Create configuration utility
    cat > $BIN_DIR/zdd-config << 'EOF'
#!/bin/bash
# Zero-Day Detector configuration utility

ZDD_DIR="/usr/local/lib/zdd"
CONFIG_DIR="/etc/zdd"

case "$1" in
    validate)
        echo "Validating configuration..."
        source $ZDD_DIR/venv/bin/activate
        python3 $ZDD_DIR/main.py --validate-config --config $CONFIG_DIR/config.yaml
        ;;
    test-rules)
        echo "Testing detection rules..."
        # Add rule testing logic here
        ;;
    health-check)
        echo "Performing health check..."
        systemctl is-active --quiet zdd-detector && echo "Service is running" || echo "Service is not running"
        ;;
    *)
        echo "Usage: zdd-config {validate|test-rules|health-check}"
        exit 1
        ;;
esac
EOF
    
    chmod +x $BIN_DIR/zdd-config
    
    # Set ownership
    chown -R $ZDD_USER:$ZDD_GROUP $INSTALL_DIR
}

# Install systemd service
install_systemd_service() {
    log_info "Installing systemd service..."
    
    if [ -f "systemd/zdd-detector.service" ]; then
        cp systemd/zdd-detector.service /etc/systemd/system/
    else
        # Create service file
        cat > /etc/systemd/system/zdd-detector.service << EOF
[Unit]
Description=Zero-Day Detector System
Documentation=https://github.com/zdd-security/detector
After=network.target
Wants=network.target

[Service]
Type=simple
User=$ZDD_USER
Group=$ZDD_GROUP
ExecStart=$BIN_DIR/zdd-detector --config $CONFIG_DIR/config.yaml
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=10

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$LOG_DIR $DATA_DIR /tmp

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096

# Capabilities needed for packet capture
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN

# Environment
Environment=PYTHONPATH=$INSTALL_DIR
Environment=ZDD_CONFIG_PATH=$CONFIG_DIR

[Install]
WantedBy=multi-user.target
EOF
    fi
    
    systemctl daemon-reload
    systemctl enable zdd-detector
}

# Configure log rotation
setup_log_rotation() {
    log_info "Setting up log rotation..."
    
    cat > /etc/logrotate.d/zdd-detector << EOF
$LOG_DIR/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 $ZDD_USER $ZDD_GROUP
    postrotate
        systemctl reload zdd-detector > /dev/null 2>&1 || true
    endscript
}
EOF
}

# Set up file permissions for log access
setup_log_permissions() {
    log_info "Setting up log file permissions..."
    
    # Add zdd-detector user to adm group for log access
    usermod -a -G adm $ZDD_USER
    
    # Set specific permissions for common log files
    if [ -f /var/log/auth.log ]; then
        chmod 644 /var/log/auth.log
    fi
    
    if [ -f /var/log/syslog ]; then
        chmod 644 /var/log/syslog
    fi
}

# Verify installation
verify_installation() {
    log_info "Verifying installation..."
    
    # Check if files exist
    if [ ! -f "$BIN_DIR/zdd-detector" ]; then
        log_error "Main executable not found"
        return 1
    fi
    
    if [ ! -f "$CONFIG_DIR/config.yaml" ]; then
        log_error "Configuration file not found"
        return 1
    fi
    
    # Test configuration
    if ! $BIN_DIR/zdd-config validate; then
        log_error "Configuration validation failed"
        return 1
    fi
    
    # Check service
    if ! systemctl is-enabled zdd-detector &>/dev/null; then
        log_error "Service not enabled"
        return 1
    fi
    
    log_info "Installation verification completed successfully"
}

# Start service
start_service() {
    log_info "Starting Zero-Day Detector service..."
    
    systemctl start zdd-detector
    
    # Wait a moment and check status
    sleep 3
    
    if systemctl is-active --quiet zdd-detector; then
        log_info "Service started successfully"
        systemctl status zdd-detector --no-pager -l
    else
        log_error "Service failed to start"
        systemctl status zdd-detector --no-pager -l
        return 1
    fi
}

# Main installation function
main() {
    log_info "Starting Zero-Day Detector installation v$ZDD_VERSION"
    
    check_root
    detect_distro
    install_dependencies
    create_user
    create_directories
    install_python_deps
    install_zdd_files
    install_systemd_service
    setup_log_rotation
    setup_log_permissions
    verify_installation
    start_service
    
    log_info "Installation completed successfully!"
    log_info ""
    log_info "Next steps:"
    log_info "1. Review configuration: $CONFIG_DIR/config.yaml"
    log_info "2. Check service status: systemctl status zdd-detector"
    log_info "3. View logs: journalctl -u zdd-detector -f"
    log_info "4. Validate config: zdd-config validate"
    log_info ""
    log_info "For more information, see the documentation."
}

# Run main function
main "$@"