#!/bin/bash

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

    if ! systemctl is-active --quiet "$service"; then
        log "Service $service is down. Attempting restart..."
        systemctl restart "$service"

        if systemctl is-active --quiet "$service"; then
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
    check_```bash
# Check main services
for service in "${SERVICES[@]}"; do
    check_and_restart_service "$service"
done

# Check vulnerable services
for vuln_service in "${VULN_SERVICES[@]}"; do
    check_and_restart_service "$vuln_service"
done
EOF

    chmod +x "$SIREN_PATH/scripts/check_services.sh"
}

# Create service files
create_service_files() {
    log "INFO" "Creating systemd service files..."

    # Example service file for vulnerable service
    cat > /etc/systemd/system/vuln.service << 'EOF'
[Unit]
Description=Vulnerable Service
After=network.target

[Service]
ExecStart=/usr/bin/python3 /opt/siren/vuln_service.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    enable_service "vuln.service"
}

# Main installation function
main_installation() {
    show_banner

    if [ "$(id -u)" -ne 0 ]; then
        log "ERROR" "This script must be run as root"
        exit 1
    fi

    mkdir -p "$SIREN_PATH/scripts"
    check_system_requirements
    create_backup

    log "INFO" "Updating system and installing dependencies..."
    apt-get update -y && apt-get upgrade -y
    apt-get install -y apache2 mysql-server php libapache2-mod-php python3-pip

    create_monitoring_scripts
    create_service_files

    log "INFO" "Enabling and starting services..."
    systemctl enable apache2 mysql
    systemctl start apache2 mysql

    log "INFO" "Installation complete. Please check logs for details."
}

main_installation
