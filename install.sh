#!/bin/bash

# SIREN - Advanced Installation and Service Manager Script
# Author: Enhanced version for practical lab use
# Description: Comprehensive setup and monitoring for SIREN vulnerable environment
# Version: 2.0

# Exit on any error
set -euo pipefail

# Enhanced color formatting with bold options
declare -r RED='\033[1;31m'
declare -r GREEN='\033[1;32m'
declare -r YELLOW='\033[1;33m'
declare -r BLUE='\033[1;34m'
declare -r CYAN='\033[1;36m'
declare -r NC='\033[0m'

# Configuration variables with defaults
declare -r SIREN_PATH="${SIREN_PATH:-/opt/siren}"
declare -r LOG_PATH="${LOG_PATH:-/var/log/siren}"
declare -r BACKUP_PATH="${BACKUP_PATH:-/var/backup/siren}"
declare -r TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
declare -r NETWORK_INTERFACE="${NETWORK_INTERFACE:-eth0}"
declare -r MAX_LOG_SIZE_MB="${MAX_LOG_SIZE_MB:-100}"
declare -r SANDBOX_NET="${SANDBOX_NET:-192.168.56.0/24}"
declare -r MIN_RAM_MB=2048
declare -r MIN_DISK_MB=10240

# Create necessary directories with proper permissions
create_directories() {
    local dirs=(
        "$SIREN_PATH"
        "$LOG_PATH"
        "$BACKUP_PATH"
        "$SIREN_PATH/scripts"
        "$SIREN_PATH/config"
        "$SIREN_PATH/data"
    )

    for dir in "${dirs[@]}"; do
        if ! mkdir -p "$dir"; then
            log "ERROR" "Failed to create directory: $dir"
            return 1
        fi
        chmod 750 "$dir"
    done
}

# Enhanced logging with rotation and proper permissions
log() {
    local level=$1
    local message=$2
    local log_file="$LOG_PATH/siren_install.log"
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    
    # Ensure log directory exists with proper permissions
    mkdir -p "$LOG_PATH"
    chmod 750 "$LOG_PATH"

    # Rotate logs if they exceed max size
    if [ -f "$log_file" ] && [ "$(stat -f %z "$log_file" 2>/dev/null || stat -c %s "$log_file")" -gt $((MAX_LOG_SIZE_MB * 1024 * 1024)) ]; then
        mv "$log_file" "$log_file.$TIMESTAMP"
        gzip "$log_file.$TIMESTAMP"
    fi

    # Enhanced logging with process ID and hostname
    local hostname=$(hostname)
    local log_message="[$timestamp][$hostname][$$][$level] $message"
    
    # Console output with colors
    case $level in
        "INFO")  echo -e "${GREEN}[+]${NC} $message" ;;
        "WARN")  echo -e "${YELLOW}[!]${NC} $message" ;;
        "ERROR") echo -e "${RED}[✗]${NC} $message" ;;
        "DEBUG") 
            if [ "${DEBUG:-0}" = "1" ]; then
                echo -e "${CYAN}[D]${NC} $message"
            fi
            ;;
        *)      echo -e "${BLUE}[*]${NC} $message" ;;
    esac

    echo "$log_message" >> "$log_file"
    chmod 640 "$log_file"
}

verify_network_isolation() {
    log "INFO" "Performing comprehensive network isolation verification..."
    
    local errors=0
    
    # Verify network interface exists
    if ! ip link show "$NETWORK_INTERFACE" &>/dev/null; then
        log "ERROR" "Network interface $NETWORK_INTERFACE does not exist"
        log "INFO" "Available interfaces:"
        ip link show | grep -E '^[0-9]+:' | cut -d: -f2
        return 1
    fi

    # Get current IP and verify it's in the sandbox network
    local current_ip=$(ip -4 addr show "$NETWORK_INTERFACE" | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
    if [ -z "$current_ip" ]; then
        log "ERROR" "Could not determine IP address on interface $NETWORK_INTERFACE"
        ((errors++))
    else
        # Verify IP is in sandbox range
        if ! python3 -c "import ipaddress; exit(0 if ipaddress.ip_address('$current_ip') in ipaddress.ip_network('$SANDBOX_NET') else 1)" 2>/dev/null; then
            log "ERROR" "IP address $current_ip is not in sandbox network $SANDBOX_NET"
            ((errors++))
        fi
    fi

    # Check for direct internet access
    local internet_check=0
    for host in "8.8.8.8" "1.1.1.1" "google.com"; do
        if ping -c 1 -W 1 "$host" &>/dev/null; then
            log "ERROR" "System has direct internet access to $host - this is not secure for a vulnerable environment"
            internet_check=1
            break
        fi
    done

    # Verify DNS resolution is properly configured
    if ! dig +short localhost &>/dev/null; then
        log "WARN" "DNS resolution may not be properly configured"
    fi

    # Check for running services on common ports
    local open_ports=$(netstat -tuln | grep LISTEN | awk '{print $4}' | cut -d: -f2)
    log "INFO" "Currently open ports: ${open_ports:-none}"

    return "$errors"
}

# Enhanced system requirements check with detailed reporting
check_system_requirements() {
    log "INFO" "Performing comprehensive system check..."
    local errors=0

    # CPU Check
    local cpu_cores=$(nproc)
    local cpu_model=$(grep "model name" /proc/cpuinfo | head -n1 | cut -d: -f2)
    local cpu_mhz=$(grep "cpu MHz" /proc/cpuinfo | head -n1 | cut -d: -f2)
    
    log "INFO" "CPU: $cpu_model ($cpu_cores cores @ ${cpu_mhz%.*} MHz)"
    if [ "$cpu_cores" -lt 2 ]; then
        log "WARN" "Less than 2 CPU cores available ($cpu_cores cores) - performance may be impacted"
        ((errors++))
    fi

    # RAM Check
    local total_ram=$(free -m | awk '/^Mem:/{print $2}')
    local available_ram=$(free -m | awk '/^Mem:/{print $7}')
    local ram_usage=$(( (total_ram - available_ram) * 100 / total_ram ))
    
    log "INFO" "RAM Usage: ${ram_usage}% ($available_ram MB free of $total_ram MB)"
    if [ "$total_ram" -lt "$MIN_RAM_MB" ]; then
        log "ERROR" "Insufficient RAM: $total_ram MB (minimum ${MIN_RAM_MB} MB required)"
        ((errors++))
    fi

    # Disk Space Check
    local root_partition="/"
    local disk_info=$(df -h "$root_partition" | awk 'NR==2 {print $2,$3,$4,$5}')
    local free_space_mb=$(df -m "$root_partition" | awk 'NR==2 {print $4}')
    
    log "INFO" "Disk Space: $disk_info"
    if [ "$free_space_mb" -lt "$MIN_DISK_MB" ]; then
        log "ERROR" "Insufficient disk space: $free_space_mb MB (minimum ${MIN_DISK_MB} MB required)"
        ((errors++))
    fi

    # Virtualization Check
    if command -v systemd-detect-virt >/dev/null; then
        if systemd-detect-virt -q; then
            local virt_type=$(systemd-detect-virt)
            log "INFO" "Running in virtualized environment: $virt_type"
            
            # Check if running in VirtualBox specifically
            if [ "$virt_type" != "oracle" ]; then
                log "WARN" "Not running in VirtualBox - some features may not work as expected"
            fi
        else
            log "ERROR" "Not running in a virtualized environment - this is not recommended"
            ((errors++))
        fi
    else
        log "WARN" "Cannot detect virtualization status - systemd-detect-virt not available"
    fi

    # Required Software Check
    local required_packages=(
        "apache2"
        "mysql-server"
        "php"
        "python3"
        "pip3"
        "ufw"
        "fail2ban"
    )

    log "INFO" "Checking required software..."
    for package in "${required_packages[@]}"; do
        if ! dpkg -l | grep -q "^ii.*$package"; then
            log "ERROR" "Required package not installed: $package"
            ((errors++))
        fi
    done

    return "$errors"
}

# Enhanced backup function with integrity verification and encryption
create_backup() {
    log "INFO" "Creating verified backup of critical files..."

    local backup_dir="$BACKUP_PATH/$TIMESTAMP"
    if ! mkdir -p "$backup_dir"; then
        log "ERROR" "Failed to create backup directory"
        return 1
    fi

    # Define critical directories to backup
    local backup_dirs=(
        "/etc/apache2"
        "/etc/mysql"
        "/etc/ssh"
        "/var/www/html"
        "$SIREN_PATH"
    )

    # Generate encryption key if needed
    local key_file="$SIREN_PATH/config/backup.key"
    if [ ! -f "$key_file" ]; then
        openssl rand -base64 32 > "$key_file"
        chmod 600 "$key_file"
    fi

    local success=0
    local failed=0

    for dir in "${backup_dirs[@]}"; do
        if [ -d "$dir" ]; then
            local backup_file="$backup_dir/$(basename "$dir").tar.gz.enc"
            
            # Create tar archive and encrypt it
            if tar czf - "$dir" 2>/dev/null | openssl enc -aes-256-cbc -salt -pbkdf2 -in - -out "$backup_file" -pass file:"$key_file"; then
                # Create SHA256 checksum of encrypted file
                sha256sum "$backup_file" > "$backup_file.sha256"
                
                # Verify backup integrity
                if sha256sum -c "$backup_file.sha256" >/dev/null 2>&1; then
                    log "INFO" "Backup created and verified: $(basename "$backup_file")"
                    ((success++))
                else
                    log "ERROR" "Backup verification failed: $(basename "$backup_file")"
                    ((failed++))
                    rm -f "$backup_file" "$backup_file.sha256"
                fi
            else
                log "ERROR" "Failed to create backup for: $dir"
                ((failed++))
            fi
        fi
    done

    # Cleanup old backups (keep last 5)
    find "$BACKUP_PATH" -maxdepth 1 -type d -mtime +5 -exec rm -rf {} \;

    log "INFO" "Backup complete: $success successful, $failed failed"
    return "$failed"
}

# Enhanced monitoring script creation with advanced features
create_monitoring_scripts() {
    log "INFO" "Creating enhanced monitoring scripts..."

    local monitor_script="$SIREN_PATH/scripts/monitor.sh"
    
    cat > "$monitor_script" << 'EOF'
#!/bin/bash

# Enhanced monitoring script with comprehensive system checks
SIREN_PATH="/opt/siren"
LOG_PATH="/var/log/siren"
CONFIG_PATH="$SIREN_PATH/config"
DATA_PATH="$SIREN_PATH/data"

# Load configuration
source "$CONFIG_PATH/monitor.conf" 2>/dev/null || {
    echo "Error: Configuration file not found"
    exit 1
}

# Initialize monitoring data files
mkdir -p "$DATA_PATH/metrics"
touch "$DATA_PATH/metrics/cpu.dat"
touch "$DATA_PATH/metrics/memory.dat"
touch "$DATA_PATH/metrics/network.dat"

# Monitoring functions
monitor_system_resources() {
    local timestamp=$(date +%s)
    
    # CPU usage
    local cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}')
    echo "$timestamp $cpu_usage" >> "$DATA_PATH/metrics/cpu.dat"
    
    # Memory usage
    local mem_total=$(free | grep Mem | awk '{print $2}')
    local mem_used=$(free | grep Mem | awk '{print $3}')
    local mem_usage=$(awk "BEGIN {printf \"%.2f\", $mem_used*100/$mem_total}")
    echo "$timestamp $mem_usage" >> "$DATA_PATH/metrics/memory.dat"
    
    # Check thresholds
    if (( $(echo "$cpu_usage > $CPU_THRESHOLD" | bc -l) )); then
        trigger_alert "CPU usage above threshold: ${cpu_usage}%"
    fi
    
    if (( $(echo "$mem_usage > $MEM_THRESHOLD" | bc -l) )); then
        trigger_alert "Memory usage above threshold: ${mem_usage}%"
    fi
}

monitor_network_activity() {
    local timestamp=$(date +%s)
    
    # Active connections
    local conn_count=$(netstat -ant | wc -l)
    echo "$timestamp $conn_count" >> "$DATA_PATH/metrics/network.dat"
    
    # Check for unusual port activity
    local unusual_ports=$(netstat -tuln | grep LISTEN | awk '{print $4}' | cut -d: -f2 | grep -vE "^($ALLOWED_PORTS)$")
    if [ -n "$unusual_ports" ]; then
        trigger_alert "Unusual ports detected: $unusual_ports"
    fi
    
    # Monitor connection attempts
    local high_conn_ips=$(netstat -ant | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | awk '$1 > $CONNECTION_LIMIT {print $2}')
    for ip in $high_conn_ips; do
        trigger_alert "High connection count from IP: $ip"
    done
}

monitor_file_integrity() {
    # Monitor critical files for changes
    local changes_detected=0
    
    # Create a new hashes database
    local hashes_db="$DATA_PATH/file_hashes.dat"
    local new_hashes_db="$DATA_PATH/file_hashes.dat.new"
    
    while IFS= read -r file; do
        if [ -f "$file" ]; then
            local current_hash=$(sha256sum "$file" | cut -d' ' -f1)
            local stored_hash=""
            
            # Check if we have a stored hash for this file
            if [ -f "$hashes_db" ]; then
                stored_hash=$(grep "^$file:" "$hashes_db" | cut -d: -f2)
            fi
            
            # Compare hashes and detect changes
            if [ -n "$stored_hash" ] && [ "$current_hash" != "$stored_hash" ]; then
                log "WARN" "File integrity change detected: $file"
                trigger_alert "File modification detected: $file"
                ((changes_detected++))
            fi
            
            # Store the current hash in the new database
            echo "$file:$current_hash" >> "$new_hashes_db"
        fi
    done < "$CONFIG_PATH/monitored_files.txt"
    
    # Rotate file hashes database
    if [ -f "$new_hashes_db" ]; then
        mv "$new_hashes_db" "$hashes_db"
    fi
    
    return "$changes_detected"
}
trigger_alert() {
    local message="$1"
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    local alert_file="$LOG_PATH/alerts.log"
    
    echo "[$timestamp] ALERT: $message" >> "$alert_file"
    
    # Execute custom alert actions if defined
    if [ -x "$CONFIG_PATH/alert_handler.sh" ]; then
        "$CONFIG_PATH/alert_handler.sh" "$message"
    fi
    
    # Send to syslog
    logger -t "SIREN" -p local0.alert "$message"
}

cleanup_old_data() {
    # Clean up old metric data files (keep last 7 days)
    find "$DATA_PATH/metrics" -type f -mtime +7 -exec rm {} \;
    
    # Compress older logs
    find "$LOG_PATH" -type f -mtime +1 -name "*.log" ! -name "*.gz" -exec gzip {} \;
}

# Main monitoring loop
main() {
    local interval="${MONITOR_INTERVAL:-60}"  # Default 60 seconds
    
    while true; do
        monitor_system_resources
        monitor_network_activity
        monitor_file_integrity
        
        # Cleanup every 24 hours
        if [ "$(($(date +%s) % 86400))" -lt "$interval" ]; then
            cleanup_old_data
        fi
        
        sleep "$interval"
    done
}

main
EOF

    # Make script executable
    chmod +x "$monitor_script"

    # Create default configuration
    local config_file="$SIREN_PATH/config/monitor.conf"
    cat > "$config_file" << 'EOF'
# SIREN Monitoring Configuration

# Thresholds
CPU_THRESHOLD=90
MEM_THRESHOLD=90
CONNECTION_LIMIT=100

# Allowed ports (comma-separated)
ALLOWED_PORTS="22,80,443,3306"

# Monitoring interval (seconds)
MONITOR_INTERVAL=60

# Alert settings
ALERT_EMAIL="admin@localhost"
ALERT_WEBHOOK=""

# Logging settings
LOG_RETENTION_DAYS=30
METRICS_RETENTION_DAYS=7
EOF
}

# Create systemd service files with proper configuration
create_service_files() {
    log "INFO" "Creating systemd service files..."

    # Main SIREN monitoring service
    cat > "/etc/systemd/system/siren-monitor.service" << 'EOF'
[Unit]
Description=SIREN Security Monitoring Service
After=network.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/opt/siren/scripts/monitor.sh
Restart=always
RestartSec=10
User=siren
Group=siren
StandardOutput=append:/var/log/siren/monitor.log
StandardError=append:/var/log/siren/monitor.error.log

# Security settings
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true
CapabilityBoundingSet=
ProtectKernelTunables=true
ProtectControlGroups=true
ProtectKernelModules=true
RestrictNamespaces=true

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd and enable service
    systemctl daemon-reload
    systemctl enable siren-monitor.service
    
    log "INFO" "Service files created and enabled"
}

# Install dependencies with error handling and verification
install_dependencies() {
    log "INFO" "Installing required packages..."
    
    # Update package lists
    if ! apt-get update; then
        log "ERROR" "Failed to update package lists"
        return 1
    }
    
    # List of required packages
    local packages=(
        apache2
        mysql-server
        php
        libapache2-mod-php
        python3
        python3-pip
        net-tools
        ufw
        fail2ban
        bc
        curl
        unzip
        git
    )
    
    # Install packages with proper error handling
    DEBIAN_FRONTEND=noninteractive apt-get install -y "${packages[@]}" || {
        log "ERROR" "Package installation failed"
        return 1
    }
    
    # Verify installations
    local failed_packages=()
    for package in "${packages[@]}"; do
        if ! dpkg -l | grep -q "^ii.*$package"; then
            failed_packages+=("$package")
        fi
    done
    
    if [ ${#failed_packages[@]} -ne 0 ]; then
        log "ERROR" "Failed to install packages: ${failed_packages[*]}"
        return 1
    fi
    
    log "INFO" "All packages installed successfully"
    return 0
}

# Main installation function
main_installation() {
    local start_time=$(date +%s)
    
    # Check for root privileges
    if [ "$(id -u)" -ne 0 ]; then
        log "ERROR" "This script must be run as root"
        exit 1
    }

    # Create lock file
    if ! mkdir /var/run/siren.lock 2>/dev/null; then
        log "ERROR" "Another instance is running or lock file exists"
        exit 1
    }

    trap 'rm -rf /var/run/siren.lock; log "INFO" "Cleanup completed"' EXIT

    # Main installation steps with error handling
    local steps=(
        "create_directories"
        "verify_network_isolation"
        "check_system_requirements"
        "install_dependencies"
        "create_backup"
        "create_monitoring_scripts"
        "create_service_files"
    )

    local failed_steps=()
    
    for step in "${steps[@]}"; do
        log "INFO" "Executing step: $step"
        if ! $step; then
            failed_steps+=("$step")
            log "ERROR" "Step failed: $step"
        fi
    done

    # Configure firewall
    ufw default deny incoming
    ufw allow from "$SANDBOX_NET"
    ufw --force enable

    # Report installation results
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    if [ ${#failed_steps[@]} -eq 0 ]; then
        log "INFO" "Installation completed successfully in $duration seconds"
    else
        log "ERROR" "Installation completed with errors in $duration seconds"
        log "ERROR" "Failed steps: ${failed_steps[*]}"
        exit 1
    fi
}

# Execute main installation
main_installation
