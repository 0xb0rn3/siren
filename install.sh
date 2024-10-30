#!/bin/bash
# SIREN - Advanced Installation and Service Manager Script
# Author: Q4n0
# Description: Comprehensive setup and monitoring for SIREN vulnerable environment

# Colors and formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
BOLD='\033[1m'
NC='\033[0m'

# Configuration
SIREN_PATH="/opt/siren"
LOG_PATH="/var/log/siren"
BACKUP_PATH="/var/backup/siren"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Banner
show_banner() {
    clear
    cat << "EOF"
███████╗██╗██████╗ ███████╗███╗   ██╗
██╔════╝██║██╔══██╗██╔════╝████╗  ██║
███████╗██║██████╔╝█████╗  ██╔██╗ ██║
╚════██║██║██╔══██╗██╔══╝  ██║╚██╗██║
███████║██║██║  ██║███████╗██║ ╚████║
╚══════╝╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝
   Vulnerable Server Creator v1.0
EOF
    echo -e "\n${BLUE}=== Created by Q4n0 ===${NC}"
    echo -e "${RED}[!] WARNING: Creates an EXTREMELY vulnerable system!"
    echo -e "[!] Use ONLY in isolated lab environments${NC}\n"
}

# Logging function
log() {
    local level=$1
    local message=$2
    local log_file="$LOG_PATH/siren_install.log"
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    
    # Create log directory if it doesn't exist
    mkdir -p "$LOG_PATH"
    
    case $level in
        "INFO")  echo -e "${GREEN}[+]${NC} $message" ;;
        "WARN")  echo -e "${YELLOW}[!]${NC} $message" ;;
        "ERROR") echo -e "${RED}[✗]${NC} $message" ;;
        *)       echo -e "${BLUE}[*]${NC} $message" ;;
    esac
    
    echo "[$timestamp] [$level] $message" >> "$log_file"
}

# Service management functions
check_service() {
    local service=$1
    if systemctl is-active --quiet $service; then
        log "INFO" "$service is running"
        return 0
    else
        log "WARN" "$service is not running. Attempting to start..."
        systemctl start $service
        if systemctl is-active --quiet $service; then
            log "INFO" "Successfully started $service"
            return 0
        else
            log "ERROR" "Failed to start $service"
            return 1
        fi
    fi
}

enable_service() {
    local service=$1
    if systemctl enable --quiet $service; then
        log "INFO" "Enabled $service on startup"
        return 0
    else
        log "ERROR" "Failed to enable $service"
        return 1
    fi
}

# Network verification function
verify_port() {
    local port=$1
    local service=$2
    if netstat -tuln | grep -q ":$port "; then
        log "INFO" "Port $port ($service) is listening"
        return 0
    else
        log "ERROR" "Port $port ($service) is not listening"
        return 1
    fi
}

# System check function
check_system_requirements() {
    log "INFO" "Checking system requirements..."
    
    # Check CPU
    local cpu_cores=$(nproc)
    if [ $cpu_cores -lt 2 ]; then
        log "WARN" "Less than 2 CPU cores available ($cpu_cores cores)"
    fi
    
    # Check RAM
    local total_ram=$(free -m | awk '/^Mem:/{print $2}')
    if [ $total_ram -lt 2048 ]; then
        log "WARN" "Less than 2GB RAM available ($total_ram MB)"
    fi
    
    # Check disk space
    local free_space=$(df -m / | awk 'NR==2 {print $4}')
    if [ $free_space -lt 10240 ]; then
        log "WARN" "Less than 10GB free space available ($free_space MB)"
    fi
}

# Backup function
create_backup() {
    log "INFO" "Creating backup of critical files..."
    
    mkdir -p "$BACKUP_PATH/$TIMESTAMP"
    
    # List of directories to backup
    local backup_dirs=(
        "/etc/apache2"
        "/etc/mysql"
        "/etc/ssh"
        "/var/www/html"
        "$SIREN_PATH"
    )
    
    for dir in "${backup_dirs[@]}"; do
        if [ -d "$dir" ]; then
            tar czf "$BACKUP_PATH/$TIMESTAMP/$(basename $dir).tar.gz" "$dir" 2>/dev/null
        fi
    done
}

# Create monitoring scripts
create_monitoring_scripts() {
    log "INFO" "Creating monitoring scripts..."
    
    # Service checker script
    cat > "$SIREN_PATH/scripts/check_services.sh" << 'EOF'
#!/bin/bash

# Service monitoring script
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

LOG_FILE="/var/log/siren/services.log"
NOTIFICATION_FILE="/var/log/siren/notifications.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

notify() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$NOTIFICATION_FILE"
}

check_and_restart_service() {
    local service=${1%:*}
    local port=${1#*:}
    
    if ! systemctl is-active --quiet $service; then
        log "Service $service is down. Attempting restart..."
        systemctl restart $service
        
        if systemctl is-active --quiet $service; then
            notify "Service $service was restarted successfully"
        else
            notify "CRITICAL: Failed to restart $service"
        fi
    fi
    
    if ! netstat -tuln | grep -q ":$port "; then
        notify "WARNING: Port $port is not listening for $service"
    fi
}

# Check main services
for service in "${SERVICES[@]}"; do
    check_and_restart_service "$service"
done

# Check vulnerable services
for service in "${VULN_SERVICES[@]}"; do
    check_and_restart_service "$service"
done

# Check SIREN Python process
if ! pgrep -f "python3 /opt/siren/siren.py" > /dev/null; then
    log "SIREN Python process is down. Restarting..."
    systemctl restart siren
    notify "SIREN Python process was restarted"
fi

# Check system resources
MEMORY_USAGE=$(free | awk '/Mem:/ {printf("%.2f"), $3/$2 * 100}')
DISK_USAGE=$(df / | awk 'NR==2 {printf("%.2f"), $3/$2 * 100}')
CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}')

if (( $(echo "$MEMORY_USAGE > 90" | bc -l) )); then
    notify "WARNING: High memory usage: ${MEMORY_USAGE}%"
fi

if (( $(echo "$DISK_USAGE > 90" | bc -l) )); then
    notify "WARNING: High disk usage: ${DISK_USAGE}%"
fi

if (( $(echo "$CPU_USAGE > 90" | bc -l) )); then
    notify "WARNING: High CPU usage: ${CPU_USAGE}%"
fi
EOF

    # Network monitor script
    cat > "$SIREN_PATH/scripts/monitor_network.sh" << 'EOF'
#!/bin/bash

LOG_FILE="/var/log/siren/network.log"
CONNECTIONS_FILE="/var/log/siren/connections.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

# Monitor suspicious connections
watch_connections() {
    netstat -antup | grep ESTABLISHED >> "$CONNECTIONS_FILE"
}

# Monitor specific ports
check_ports() {
    local ports=(21 22 80 443 3306 4444 4445 4446 5555)
    for port in "${ports[@]}"; do
        if netstat -tuln | grep -q ":$port "; then
            log "Port $port is listening"
        else
            log "WARNING: Port $port is not listening"
        fi
    done
}

# Main monitoring loop
while true; do
    watch_connections
    check_ports
    sleep 60
done
EOF

    chmod +x "$SIREN_PATH/scripts/"*.sh
}

# Create service files
create_service_files() {
    log "INFO" "Creating service files..."
    
    # SIREN main service
    cat > "/etc/systemd/system/siren.service" << EOF
[Unit]
Description=SIREN Vulnerable Environment
After=network.target mysql.service apache2.service
Wants=apache2.service mysql.service ssh.service vsftpd.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 $SIREN_PATH/siren.py
Restart=always
RestartSec=10
User=root
WorkingDirectory=$SIREN_PATH

[Install]
WantedBy=multi-user.target
EOF

    # Monitoring service
    cat > "/etc/systemd/system/siren-monitor.service" << EOF
[Unit]
Description=SIREN Service Monitor
After=siren.service

[Service]
Type=simple
ExecStart=$SIREN_PATH/scripts/check_services.sh
Restart=always
RestartSec=60
User=root

[Install]
WantedBy=multi-user.target
EOF

    # Network monitoring service
    cat > "/etc/systemd/system/siren-network.service" << EOF
[Unit]
Description=SIREN Network Monitor
After=network.target

[Service]
Type=simple
ExecStart=$SIREN_PATH/scripts/monitor_network.sh
Restart=always
RestartSec=60
User=root

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
}

# Main installation function
main() {
    show_banner
    
    # Check root
    if [ "$EUID" -ne 0 ]; then 
        log "ERROR" "Please run as root"
        exit 1
    fi

    log "INFO" "Starting SIREN installation..."
    
    # Create directories
    mkdir -p "$SIREN_PATH"/{scripts,logs,data,backup}
    mkdir -p "$LOG_PATH"
    mkdir -p "$BACKUP_PATH"
    
    # Check system requirements
    check_system_requirements
    
    # Create backup
    create_backup
    
    # Update system
    log "INFO" "Updating system..."
    apt update && apt upgrade -y
    
    # Install dependencies
    log "INFO" "Installing dependencies..."
    apt install -y \
        python3 \
        python3-pip \
        python3-dev \
        build-essential \
        libssl-dev \
        libffi-dev \
        apache2 \
        php \
        php-mysql \
        mysql-server \
        openssh-server \
        vsftpd \
        gcc \
        make \
        git \
        curl \
        wget \
        netcat \
        nmap \
        tcpdump \
        bc \
        net-tools
    
    # Install Python packages
    log "INFO" "Installing Python packages..."
    pip3 install -r requirements.txt
    
    # Create monitoring scripts
    create_monitoring_scripts
    
    # Create service files
    create_service_files
    
    # Enable services
    log "INFO" "Enabling services..."
    services=("siren" "siren-monitor" "siren-network")
    for service in "${services[@]}"; do
        enable_service $service
        check_service $service
    done
    
    # Create cron jobs
    log "INFO" "Setting up cron jobs..."
    echo "*/5 * * * * root $SIREN_PATH/scripts/check_services.sh" > /etc/cron.d/siren
    echo "@reboot root $SIREN_PATH/scripts/monitor_network.sh" >> /etc/cron.d/siren
    
    # Final checks
    log "INFO" "Performing final checks..."
    verify_port 80 "Apache"
    verify_port 3306 "MySQL"
    verify_port 22 "SSH"
    verify_port 21 "FTP"
    
    log "INFO" "SIREN installation completed successfully!"
    echo -e "\n${GREEN}[+] Installation complete! System is now vulnerable and monitored.${NC}"
    echo -e "${RED}[!] WARNING: Use only in isolated environments!${NC}"
}

# Run main installation
main
