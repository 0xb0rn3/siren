#!/bin/bash

# SIREN - Advanced Installation and Service Manager Script
# Author: Original by 0xb0rn3, Enhanced version
# Description: Comprehensive setup and monitoring for SIREN vulnerable environment
# Warning: Creates intentionally vulnerable systems - Use ONLY in isolated lab environments

# Enhanced color formatting with bold options
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
CYAN='\033[1;36m'
NC='\033[0m'

# Configuration with additional safety measures
SIREN_PATH="/opt/siren"
LOG_PATH="/var/log/siren"
BACKUP_PATH="/var/backup/siren"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
NETWORK_INTERFACE="eth0"  # Default interface, will be checked later
MAX_LOG_SIZE_MB=100
SANDBOX_NET="192.168.56.0/24"  # Isolated network range

# Trap errors and cleanup
cleanup() {
    local exit_code=$?
    log "INFO" "Cleaning up temporary files..."
    rm -f /tmp/siren_*
    if [ $exit_code -ne 0 ]; then
        log "ERROR" "Script failed with exit code $exit_code. Check logs for details."
    fi
    exit $exit_code
}
trap cleanup EXIT

# Enhanced logging with rotation
log() {
    local level=$1
    local message=$2
    local log_file="$LOG_PATH/siren_install.log"
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    
    mkdir -p "$LOG_PATH"

    # Rotate logs if they exceed max size
    if [ -f "$log_file" ] && [ $(du -m "$log_file" | cut -f1) -gt $MAX_LOG_SIZE_MB ]; then
        mv "$log_file" "$log_file.$TIMESTAMP"
        gzip "$log_file.$TIMESTAMP"
    fi

    # Enhanced logging with process ID and more detailed formatting
    case $level in
        "INFO")  echo -e "${GREEN}[+] [$$]${NC} $message" ;;
        "WARN")  echo -e "${YELLOW}[!] [$$]${NC} $message" ;;
        "ERROR") echo -e "${RED}[✗] [$$]${NC} $message" ;;
        "DEBUG") 
            if [ "${DEBUG:-0}" = "1" ]; then
                echo -e "${CYAN}[D] [$$]${NC} $message"
            fi
            ;;
        *)       echo -e "${BLUE}[*] [$$]${NC} $message" ;;
    esac

    echo "[$timestamp] [$$] [$level] $message" >> "$log_file"
}

# Network isolation verification
verify_network_isolation() {
    log "INFO" "Verifying network isolation..."
    
    # Check if running in isolated network
    current_ip=$(ip addr show $NETWORK_INTERFACE 2>/dev/null | grep inet | awk '{print $2}' | head -n1)
    if [ -z "$current_ip" ]; then
        log "ERROR" "Could not determine IP address on interface $NETWORK_INTERFACE"
        return 1
    fi

    # Verify no direct internet access (optional)
    if ping -c 1 -W 1 8.8.8.8 >/dev/null 2>&1; then
        log "WARN" "System has direct internet access - this is not recommended for vulnerable environments"
    else
        log "INFO" "Network appears to be properly isolated"
    fi
}

# Enhanced system requirements check
check_system_requirements() {
    log "INFO" "Performing comprehensive system check..."

    # CPU Check with detailed info
    local cpu_cores=$(nproc)
    local cpu_model=$(grep "model name" /proc/cpuinfo | head -n1 | cut -d: -f2)
    log "INFO" "CPU: $cpu_model ($cpu_cores cores)"
    [ "$cpu_cores" -lt 2 ] && log "WARN" "Less than 2 CPU cores available ($cpu_cores cores)"

    # RAM Check with percentage utilization
    local total_ram=$(free -m | awk '/^Mem:/{print $2}')
    local used_ram=$(free -m | awk '/^Mem:/{print $3}')
    local ram_usage=$((used_ram * 100 / total_ram))
    log "INFO" "RAM Usage: ${ram_usage}% ($used_ram MB / $total_ram MB)"
    [ "$total_ram" -lt 2048 ] && log "WARN" "Less than 2GB RAM available ($total_ram MB)"

    # Enhanced disk space check
    local disk_info=$(df -h / | awk 'NR==2 {print $2,$3,$4,$5}')
    log "INFO" "Disk Space: $disk_info"
    local free_space=$(df -m / | awk 'NR==2 {print $4}')
    [ "$free_space" -lt 10240 ] && log "WARN" "Less than 10GB free space available ($free_space MB)"

    # Virtualization check
    if systemd-detect-virt -q; then
        local virt_type=$(systemd-detect-virt)
        log "INFO" "Running in virtualized environment: $virt_type"
    else
        log "WARN" "Not running in a virtualized environment - this is not recommended"
    fi
}

# Enhanced backup function with integrity verification
create_backup() {
    log "INFO" "Creating verified backup of critical files..."

    local backup_dir="$BACKUP_PATH/$TIMESTAMP"
    mkdir -p "$backup_dir"

    local backup_dirs=(
        "/etc/apache2"
        "/etc/mysql"
        "/etc/ssh"
        "/var/www/html"
        "$SIREN_PATH"
    )

    for dir in "${backup_dirs[@]}"; do
        if [ -d "$dir" ]; then
            local backup_file="$backup_dir/$(basename "$dir").tar.gz"
            tar czf "$backup_file" "$dir" 2>/dev/null
            
            # Create SHA256 checksum
            sha256sum "$backup_file" > "$backup_file.sha256"
            
            # Verify backup integrity
            if sha256sum -c "$backup_file.sha256" >/dev/null 2>&1; then
                log "INFO" "Backup created and verified: $(basename "$backup_file")"
            else
                log "ERROR" "Backup verification failed for: $(basename "$backup_file")"
            fi
        fi
    done

    # Maintain only last 5 backups
    find "$BACKUP_PATH" -maxdepth 1 -type d -mtime +5 -exec rm -rf {} \;
}

# Enhanced monitoring script creation
create_monitoring_scripts() {
    log "INFO" "Creating enhanced monitoring scripts..."

    cat > "$SIREN_PATH/scripts/monitor.sh" << 'EOF'
#!/bin/bash

# Enhanced monitoring script with resource tracking and alerts
SERVICES=(
    "apache2:80"
    "mysql:3306"
    "ssh:22"
    "vsftpd:21"
    "siren:4444"
)

VULN_SERVICES=(
    "vuln-service:5555"
    "monitor:4445"
    "backdoor:4446"
)

LOG_PATH="/var/log/siren"
ALERT_THRESHOLD=90  # CPU/RAM threshold for alerts

# Resource monitoring function
monitor_resources() {
    local cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d. -f1)
    local mem_usage=$(free | grep Mem | awk '{print $3/$2 * 100.0}' | cut -d. -f1)
    
    if [ "$cpu_usage" -gt "$ALERT_THRESHOLD" ] || [ "$mem_usage" -gt "$ALERT_THRESHOLD" ]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] ALERT: High resource usage - CPU: ${cpu_usage}%, RAM: ${mem_usage}%" >> "$LOG_PATH/alerts.log"
    fi
}

# Network connection monitoring
monitor_connections() {
    local conn_count=$(netstat -ant | wc -l)
    if [ "$conn_count" -gt 1000 ]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] ALERT: High number of connections: $conn_count" >> "$LOG_PATH/alerts.log"
    fi
}

# Main monitoring loop
while true; do
    monitor_resources
    monitor_connections
    sleep 60
done
EOF

    chmod +x "$SIREN_PATH/scripts/monitor.sh"
}

# Create systemd service for monitoring
create_service_files() {
    log "INFO" "Creating enhanced systemd service files..."

    # Monitoring service
    cat > /etc/systemd/system/siren-monitor.service << 'EOF'
[Unit]
Description=SIREN Monitoring Service
After=network.target

[Service]
Type=simple
ExecStart=/opt/siren/scripts/monitor.sh
Restart=always
StandardOutput=append:/var/log/siren/monitor.log
StandardError=append:/var/log/siren/monitor.error.log

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    enable_service "siren-monitor.service"
}

# Main installation function with enhanced error handling
main_installation() {
    show_banner
    
    # Check for root privileges
    if [ "$(id -u)" -ne 0 ]; then
        log "ERROR" "This script must be run as root"
        exit 1
    }

    # Create lock file to prevent multiple instances
    if ! mkdir /var/run/siren.lock 2>/dev/null; then
        log "ERROR" "Another instance is running or lock file exists"
        exit 1
    fi

    # Initialize with error handling
    set -eE
    trap 'log "ERROR" "Line $LINENO: Command failed with exit code $?"' ERR

    # Main installation steps
    verify_network_isolation
    check_system_requirements
    create_backup
    
    log "INFO" "Installing dependencies..."
    DEBIAN_FRONTEND=noninteractive apt-get update -y
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        apache2 mysql-server php libapache2-mod-php python3-pip \
        net-tools netstat-nat ufw fail2ban

    create_monitoring_scripts
    create_service_files

    # Configure basic firewall for lab network
    ufw default deny incoming
    ufw allow from "$SANDBOX_NET"
    ufw --force enable

    log "INFO" "Installation complete. Please check logs at $LOG_PATH for details."
}

# Execute main installation
main_installation
