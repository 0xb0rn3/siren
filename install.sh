#!/bin/bash
# SIREN Installation Handler

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}[+] SIREN Installation Handler${NC}"

# Check root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}[!] Please run as root${NC}"
    exit 1
fi

# Create SIREN directory
mkdir -p /opt/siren
cd /opt/siren

# Update system
echo -e "${GREEN}[+] Updating system...${NC}"
apt update && apt upgrade -y

# Install Python and dependencies
echo -e "${GREEN}[+] Installing Python and dependencies...${NC}"
apt install -y \
    python3 \
    python3-pip \
    python3-dev \
    build-essential \
    libssl-dev \
    libffi-dev \
    python3-setuptools \
    git \
    apache2 \
    mysql-server \
    php \
    libapache2-mod-php \
    php-mysql \
    openssh-server \
    vsftpd \
    gcc \
    make \
    nmap

# Install Python packages
echo -e "${GREEN}[+] Installing Python packages...${NC}"
pip3 install \
    flask \
    sqlalchemy \
    colorama \
    paramiko \
    scapy \
    psutil \
    requests \
    pycryptodome \
    python-nmap \
    pyOpenSSL

# Clone SIREN files
echo -e "${GREEN}[+] Setting up SIREN...${NC}"
git clone https://github.com/q4n0/siren.git /opt/siren || {
    echo -e "${RED}[!] Git clone failed, creating directory structure...${NC}"
    mkdir -p /opt/siren/{modules,templates,static}
}

# Create project structure
mkdir -p /opt/siren/modules
mkdir -p /opt/siren/templates
mkdir -p /opt/siren/static
mkdir -p /var/www/html/uploads

# Set permissions
chmod 777 /var/www/html/uploads

# Create symlink
ln -s /opt/siren/siren.py /usr/local/bin/siren

echo -e "${GREEN}[+] SIREN installed successfully!${NC}"
echo -e "${YELLOW}[*] Run 'siren' to start the tool${NC}"
