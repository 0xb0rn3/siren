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
import json
from datetime import datetime
import hashlib
from pathlib import Path
import secrets
import tempfile
from contextlib import contextmanager
import signal
from typing import Dict, List, Optional, Union
from functools import wraps
from dataclasses import dataclass
import time
import queue
import re
import ipaddress

from colorama import init, Fore, Style
from flask import Flask, request, render_template_string, send_file, jsonify
import paramiko
import psutil
import scapy.all as scapy
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import nmap

@dataclass
class VulnerabilityConfig:
    """Configuration for vulnerability types"""
    name: str
    enabled: bool
    risk_level: str
    description: str
    mitigation: str

class SecurityMonitor:
    """Handles security monitoring and alerts"""
    def __init__(self, logger):
        self.logger = logger
        self.alert_queue = queue.Queue()
        self.baseline_stats = {}
        self.anomaly_threshold = 2.0
        
    def check_anomaly(self, metric: str, value: float) -> bool:
        """Check if a metric shows anomalous behavior"""
        if metric not in self.baseline_stats:
            self.baseline_stats[metric] = {'mean': value, 'count': 1}
            return False
            
        stats = self.baseline_stats[metric]
        deviation = abs(value - stats['mean'])
        is_anomaly = deviation > (stats['mean'] * self.anomaly_threshold)
        
        # Update running statistics
        stats['mean'] = ((stats['mean'] * stats['count']) + value) / (stats['count'] + 1)
        stats['count'] += 1
        
        return is_anomaly

class SIREN:
    def __init__(self):
        """Initialize SIREN with enhanced security features"""
        self.banner = """[Banner remains the same]"""
        self._init_security()
        self.app = self._create_flask_app()
        self._setup_logging()
        self.config = self._load_config()
        self.monitor = SecurityMonitor(self.logger)
        self.web_root = Path("/var/www/html")
        self.upload_dir = self.web_root / "uploads"
        self.backup_dir = Path("/var/backup/siren")
        self._setup_paths()
        self._init_encryption()
        
    def _init_security(self):
        """Initialize security measures and state tracking"""
        self.session_key = secrets.token_hex(32)
        self.active_services = {}
        self.connection_limits = {}
        self.blocked_ips = set()
        self.file_hashes = {}
        self.last_backup = None
        
    def _init_encryption(self):
        """Setup encryption for sensitive data"""
        self.encryption_key = get_random_bytes(32)
        self.cipher = AES.new(self.encryption_key, AES.MODE_GCM)
        
    def _encrypt_sensitive_data(self, data: str) -> dict:
        """Encrypt sensitive data with AES-GCM"""
        cipher = AES.new(self.encryption_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data.encode())
        return {
            'ciphertext': ciphertext,
            'nonce': cipher.nonce,
            'tag': tag
        }
        
    def _decrypt_sensitive_data(self, encrypted_data: dict) -> str:
        """Decrypt sensitive data"""
        cipher = AES.new(self.encryption_key, AES.MODE_GCM, nonce=encrypted_data['nonce'])
        plaintext = cipher.decrypt_and_verify(encrypted_data['ciphertext'], encrypted_data['tag'])
        return plaintext.decode()

    def _setup_logging(self):
        """Enhanced logging configuration with rotation and encryption"""
        log_config = {
            'version': 1,
            'handlers': {
                'file': {
                    'class': 'logging.handlers.RotatingFileHandler',
                    'filename': 'siren.log',
                    'maxBytes': 10485760,  # 10MB
                    'backupCount': 5,
                    'formatter': 'detailed',
                    'encoding': 'utf-8'
                },
                'security': {
                    'class': 'logging.handlers.RotatingFileHandler',
                    'filename': 'security.log',
                    'maxBytes': 10485760,
                    'backupCount': 5,
                    'formatter': 'detailed',
                    'encoding': 'utf-8'
                }
            },
            'formatters': {
                'detailed': {
                    'format': '%(asctime)s - [%(levelname)s] - %(name)s - %(message)s',
                    'datefmt': '%Y-%m-%d %H:%M:%S'
                }
            },
            'loggers': {
                'siren': {
                    'handlers': ['file', 'security'],
                    'level': 'INFO'
                }
            }
        }
        logging.config.dictConfig(log_config)
        self.logger = logging.getLogger('siren')

    @contextmanager
    def _secure_temp_file(self) -> Path:
        """Create and manage secure temporary files"""
        temp_file = None
        try:
            with tempfile.NamedTemporaryFile(delete=False) as tf:
                temp_file = Path(tf.name)
                yield temp_file
        finally:
            if temp_file and temp_file.exists():
                temp_file.unlink()

    def _rate_limit(self, func):
        """Decorator for rate limiting requests"""
        @wraps(func)
        def wrapper(*args, **kwargs):
            client_ip = request.remote_addr
            current_time = time.time()
            
            if client_ip in self.blocked_ips:
                return jsonify({'error': 'IP is blocked'}), 403
                
            if client_ip not in self.connection_limits:
                self.connection_limits[client_ip] = []
            
            # Clean old requests
            self.connection_limits[client_ip] = [
                t for t in self.connection_limits[client_ip]
                if current_time - t < 60
            ]
            
            if len(self.connection_limits[client_ip]) >= self.config['MAX_REQUESTS_PER_MINUTE']:
                self.blocked_ips.add(client_ip)
                self.logger.warning(f"IP {client_ip} blocked for excessive requests")
                return jsonify({'error': 'Rate limit exceeded'}), 429
                
            self.connection_limits[client_ip].append(current_time)
            return func(*args, **kwargs)
        return wrapper

    def create_upload_vulnerability(self):
        """Create file upload vulnerability with enhanced monitoring"""
        upload_code = '''
<?php
function generateSecureFilename($extension) {
    return bin2hex(random_bytes(16)) . $extension;
}

function logUpload($filename, $ip) {
    $log_file = '/var/log/siren/uploads.log';
    $timestamp = date('Y-m-d H:i:s');
    $log_entry = sprintf("[%s] Upload: %s from %s\\n", 
        $timestamp, $filename, $ip);
    file_put_contents($log_file, $log_entry, FILE_APPEND);
}

if(isset($_FILES['file'])) {
    $file = $_FILES['file'];
    $name = $file['name'];
    $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
    
    // Enhanced validation
    $allowed = array('txt', 'php', 'html', 'jpg', 'png');
    $max_size = 10 * 1024 * 1024; // 10MB
    
    if(!in_array($ext, $allowed)) {
        die('File type not allowed');
    }
    
    if($file['size'] > $max_size) {
        die('File too large');
    }
    
    $newname = generateSecureFilename("." . $ext);
    $path = "uploads/" . $newname;
    
    if(move_uploaded_file($file['tmp_name'], $path)) {
        logUpload($newname, $_SERVER['REMOTE_ADDR']);
        echo "File uploaded to: " . htmlspecialchars($path);
    }
}
?>
<form method="POST" enctype="multipart/form-data">
    <input type="file" name="file">
    <input type="submit" value="Upload">
</form>
'''
        self._write_php_file("upload.php", upload_code)

    def setup_monitoring(self):
        """Setup comprehensive system monitoring"""
        monitors = [
            self._monitor_system_resources,
            self._monitor_network_traffic,
            self._monitor_file_changes,
            self._monitor_authentication,
            self._monitor_services,
            self._monitor_vulnerabilities
        ]
        
        for monitor in monitors:
            thread = threading.Thread(target=monitor, daemon=True)
            thread.start()

    def _monitor_vulnerabilities(self):
        """Monitor exploitation attempts"""
        while True:
            try:
                self._check_upload_attempts()
                self._check_sql_injection()
                self._check_rce_attempts()
                self._check_authentication_bypass()
                time.sleep(self.config['MONITORING_INTERVAL'])
            except Exception as e:
                self.logger.error(f"Vulnerability monitoring error: {e}")

    def create_backup(self):
        """Create encrypted backup of critical data"""
        backup_time = datetime.now()
        backup_path = self.backup_dir / f"backup_{backup_time:%Y%m%d_%H%M%S}"
        
        try:
            backup_path.mkdir(parents=True, exist_ok=True)
            
            # Backup configuration
            config_backup = backup_path / "config.enc"
            encrypted_config = self._encrypt_sensitive_data(
                json.dumps(self.config)
            )
            with open(config_backup, 'wb') as f:
                f.write(json.dumps(encrypted_config).encode())
            
            # Backup logs
            log_backup = backup_path / "logs.tar.gz"
            subprocess.run([
                "tar", "czf", str(log_backup),
                "/var/log/siren"
            ], check=True)
            
            self.last_backup = backup_time
            self.logger.info(f"Backup created at {backup_path}")
            
        except Exception as e:
            self.logger.error(f"Backup failed: {e}")
