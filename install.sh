#!/bin/bash
# SIREN Installation Script

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

echo -e "${GREEN}[+] Installing SIREN dependencies...${NC}"

# Check root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}[!] Please run as root${NC}"
    exit 1
fi

# Update and install dependencies
apt update
apt install -y \
    python3 \
    python3-pip \
    python3-dev \
    build-essential \
    libssl-dev \
    libffi-dev \
    apache2 \
    php \
    mysql-server \
    openssh-server \
    vsftpd \
    gcc \
    make \
    git \
    curl \
    wget

# Install Python packages
pip3 install -r requirements.txt

echo -e "${GREEN}[+] Installation complete!${NC}"
