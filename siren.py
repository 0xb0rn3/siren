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
import logging.config
import json
from datetime import datetime, timedelta
import hashlib
from pathlib import Path
import secrets
import tempfile
from contextlib import contextmanager
import signal
from typing import Dict, List, Optional, Union, Tuple
from functools import wraps
from dataclasses import dataclass
import time
import queue
import re
import ipaddress
import traceback

from colorama import init, Fore, Style
from flask import Flask, request, render_template_string, send_file, jsonify, Response
import paramiko
import psutil
import scapy.all as scapy
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import nmap
from prometheus_client import Counter, Gauge, start_http_server

# Initialize colorama for cross-platform colored output
init()

@dataclass
class VulnerabilityConfig:
    """Configuration for vulnerability types with enhanced tracking"""
    name: str
    enabled: bool
    risk_level: str  # 'low', 'medium', 'high', 'critical'
    description: str
    mitigation: str
    detection_patterns: List[str]  # Regex patterns to detect exploitation attempts
    max_attempts: int  # Maximum allowed attempts before alerting
    cooldown_period: int  # Seconds to wait after max_attempts reached
    last_triggered: datetime = None
    attempt_count: int = 0

class SecurityEvent:
    """Represents a security-relevant event in the system"""
    def __init__(self, event_type: str, severity: str, details: dict):
        self.timestamp = datetime.now()
        self.event_type = event_type
        self.severity = severity
        self.details = details
        self.event_id = secrets.token_hex(8)

    def to_dict(self) -> dict:
        """Convert event to dictionary format for logging/storage"""
        return {
            'event_id': self.event_id,
            'timestamp': self.timestamp.isoformat(),
            'type': self.event_type,
            'severity': self.severity,
            'details': self.details
        }

class SecurityMonitor:
    """Enhanced security monitoring and alerting system"""
    def __init__(self, logger):
        self.logger = logger
        self.alert_queue = queue.Queue()
        self.baseline_stats = {}
        self.anomaly_threshold = 2.0
        self.events = queue.Queue(maxsize=1000)
        self.metrics = self._setup_metrics()
        
    def _setup_metrics(self) -> Dict:
        """Initialize Prometheus metrics for monitoring"""
        return {
            'security_events': Counter(
                'siren_security_events_total',
                'Total security events by type',
                ['event_type', 'severity']
            ),
            'system_load': Gauge(
                'siren_system_load',
                'Current system load average'
            ),
            'memory_usage': Gauge(
                'siren_memory_usage_bytes',
                'Current memory usage in bytes'
            ),
            'active_connections': Gauge(
                'siren_active_connections',
                'Number of active network connections'
            )
        }
        
    def record_event(self, event: SecurityEvent):
        """Record and analyze security events"""
        # Update metrics
        self.metrics['security_events'].labels(
            event_type=event.event_type,
            severity=event.severity
        ).inc()
        
        # Store event
        try:
            self.events.put_nowait(event)
        except queue.Full:
            # Remove oldest event if queue is full
            self.events.get_nowait()
            self.events.put_nowait(event)
            
        # Log event
        self.logger.warning(f"Security Event: {event.to_dict()}")
        
        # Check for anomalies
        if self.check_anomaly(event.event_type, 1.0):
            self.trigger_alert(event)

    def trigger_alert(self, event: SecurityEvent):
        """Handle security alerts"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'event': event.to_dict(),
            'recommendations': self._get_recommendations(event)
        }
        
        self.alert_queue.put(alert)
        self.logger.error(f"Security Alert Triggered: {alert}")

    def _get_recommendations(self, event: SecurityEvent) -> List[str]:
        """Generate security recommendations based on event type"""
        recommendations = {
            'unauthorized_access': [
                'Review access logs for suspicious patterns',
                'Verify authentication mechanisms',
                'Check for compromised credentials'
            ],
            'file_modification': [
                'Compare file checksums with known good values',
                'Review file permissions',
                'Check for unauthorized processes'
            ],
            'network_anomaly': [
                'Analyze network traffic patterns',
                'Review firewall rules',
                'Check for unauthorized services'
            ]
        }
        return recommendations.get(event.event_type, ['Investigate suspicious activity'])

class SIREN:
    """Enhanced SIREN vulnerability lab creator with improved security features"""
    def __init__(self):
        """Initialize SIREN with comprehensive security controls"""
        self.start_time = datetime.now()
        self._init_security()
        self.app = self._create_flask_app()
        self._setup_logging()
        self.config = self._load_config()
        self.monitor = SecurityMonitor(self.logger)
        self._setup_paths()
        self._init_encryption()
        self._setup_metrics_server()
        self.vulnerability_configs = self._load_vulnerability_configs()
        
    def _init_security(self):
        """Initialize enhanced security measures"""
        # Generate strong cryptographic keys
        self.session_key = secrets.token_bytes(32)
        self.hmac_key = secrets.token_bytes(32)
        
        # Security state tracking
        self.active_services: Dict[str, Dict] = {}
        self.connection_limits: Dict[str, List[float]] = {}
        self.blocked_ips: Dict[str, datetime] = {}
        self.file_hashes: Dict[str, str] = {}
        self.auth_failures: Dict[str, List[datetime]] = {}
        self.last_backup: Optional[datetime] = None
        self.service_states: Dict[str, bool] = {}
        
        # Load IP blacklist
        self.ip_blacklist = self._load_ip_blacklist()
        
    def _setup_metrics_server(self):
        """Initialize Prometheus metrics endpoint"""
        # Start metrics server on a separate port
        self.metrics_port = 9090
        start_http_server(self.metrics_port)
        
        # Define additional metrics
        self.metrics = {
            'requests': Counter(
                'siren_requests_total',
                'Total HTTP requests',
                ['endpoint', 'method', 'status']
            ),
            'vulnerability_triggers': Counter(
                'siren_vulnerability_triggers_total',
                'Vulnerability trigger attempts',
                ['vulnerability_type', 'success']
            ),
            'active_sessions': Gauge(
                'siren_active_sessions',
                'Number of active user sessions'
            )
        }

    def _load_vulnerability_configs(self) -> Dict[str, VulnerabilityConfig]:
        """Load and validate vulnerability configurations"""
        with open('vulnerability_configs.json') as f:
            configs = json.load(f)
            
        return {
            name: VulnerabilityConfig(
                name=name,
                enabled=config['enabled'],
                risk_level=config['risk_level'],
                description=config['description'],
                mitigation=config['mitigation'],
                detection_patterns=config['detection_patterns'],
                max_attempts=config['max_attempts'],
                cooldown_period=config['cooldown_period']
            )
            for name, config in configs.items()
        }

    @contextmanager
    def _secure_operation(self, operation_name: str) -> None:
        """Context manager for secure operations with proper cleanup"""
        start_time = time.time()
        try:
            self.logger.debug(f"Starting {operation_name}")
            yield
        except Exception as e:
            self.logger.error(f"Error in {operation_name}: {str(e)}")
            self.monitor.record_event(SecurityEvent(
                'operation_error',
                'high',
                {'operation': operation_name, 'error': str(e)}
            ))
            raise
        finally:
            duration = time.time() - start_time
            self.logger.debug(f"Completed {operation_name} in {duration:.2f}s")

    def create_vulnerability(self, vuln_type: str) -> None:
        """Create a specific vulnerability with monitoring"""
        config = self.vulnerability_configs.get(vuln_type)
        if not config or not config.enabled:
            raise ValueError(f"Vulnerability type {vuln_type} not enabled or not found")
            
        with self._secure_operation(f"create_vulnerability_{vuln_type}"):
            # Create the vulnerability based on type
            if vuln_type == "file_upload":
                self.create_upload_vulnerability()
            elif vuln_type == "sql_injection":
                self.create_sql_vulnerability()
            elif vuln_type == "command_injection":
                self.create_command_vulnerability()
            
            self.logger.info(f"Created {vuln_type} vulnerability")
            self.monitor.record_event(SecurityEvent(
                'vulnerability_created',
                'medium',
                {'type': vuln_type, 'config': config.to_dict()}
            ))

    def monitor_exploitation(self, vuln_type: str, request_data: dict) -> bool:
        """Monitor and detect exploitation attempts"""
        config = self.vulnerability_configs.get(vuln_type)
        if not config:
            return False
            
        # Check for exploitation patterns
        for pattern in config.detection_patterns:
            if any(re.search(pattern, str(value)) for value in request_data.values()):
                config.attempt_count += 1
                
                # Record the attempt
                self.monitor.record_event(SecurityEvent(
                    'exploitation_attempt',
                    'high',
                    {
                        'vulnerability': vuln_type,
                        'pattern_matched': pattern,
                        'request_data': request_data,
                        'client_ip': request.remote_addr
                    }
                ))
                
                # Check if we should block further attempts
                if config.attempt_count >= config.max_attempts:
                    if not config.last_triggered or \
                       (datetime.now() - config.last_triggered).seconds > config.cooldown_period:
                        config.last_triggered = datetime.now()
                        config.attempt_count = 0
                        return True
                        
        return False

    def _validate_file_upload(self, file) -> Tuple[bool, str]:
        """Validate file uploads with enhanced security checks"""
        # Basic file checks
        if not file or not file.filename:
            return False, "No file provided"
            
        # Size validation
        if file.content_length > self.config['MAX_UPLOAD_SIZE']:
            return False, "File too large"
            
        # Extension validation
        ext = Path(file.filename).suffix.lower()
        if ext not in self.config['ALLOWED_EXTENSIONS']:
            return False, "File type not allowed"
            
        # Content validation
        try:
            content = file.read(1024)  # Read first 1KB for validation
            file.seek(0)  # Reset file pointer
            
            # Check for executable content
            if b'\x7fELF' in content or b'MZ' in content:
                return False, "Executable files not allowed"
                
            # Additional content validation based on extension
            if ext == '.php':
                php_patterns = [b'<?php', b'<?=', b'<script']
                if any(pattern in content for pattern in php_patterns):
                    self.monitor.record_event(SecurityEvent(
                        'malicious_upload',
                        'high',
                        {'filename': file.filename, 'patterns_found': 'php_code'}
                    ))
                    return False, "PHP code not allowed"
                    
        except Exception as e:
            self.logger.error(f"File validation error: {e}")
            return False, "File validation failed"
            
        return True, ""

    def handle_upload(self):
        """Handle file uploads with security monitoring"""
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
            
        file = request.files['file']
        valid, error = self._validate_file_upload(file)
        
        if not valid:
            self.monitor.record_event(SecurityEvent(
                'invalid_upload',
                'medium',
                {'error': error, 'filename': file.filename}
            ))
            return jsonify({'error': error}), 400
            
        # Generate secure filename
        secure_filename = secrets.token_hex(16) + Path(file.filename).suffix
        
        try:
            # Save file with proper permissions
            upload_path = self.upload_dir / secure_filename
            file.save(upload_path)
            os.chmod(upload_path, 0o644)
            
            # Calculate file hash
            file_hash = hashlib.sha256()
            with open(upload_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    file_hash.update(chunk)
                    
            self.file_hashes[str(upload_path)] = file_hash.hexdigest()
            
            self.monitor.record_event(SecurityEvent(
                'file_uploaded',
                'info',
                {
                    'filename': secure_filename,
                    'size': os.path.getsize(upload_path),
                    'hash': self.file_hashes[str(upload_path)]
                }
            ))
            
            return jsonify({
                'success': True,
                'filename': secure_filename,
                'path': str(upload_path)
            })
            
        except Exception as e:
            self.logger.error(f"Upload error: {e}")
            return jsonify({'error': 'Upload failed'}), 500

    def run(self):
        """Run the SIREN application with enhanced monitoring"""
        try:
            # Start monitoring threads
            self.setup_monitoring()
            
            # Start the Flask application
            self.app.run(
                host=self.config['HOST'],
                port=self.config['PORT'],
                ssl_context=self._setup_ssl() if self.config['USE_SSL'] else None
            )
        except Exception as e:
            self.logger.critical(f"Application startup failed: {e}")
            sys.exit(1)
        finally:
            self._cleanup()

if __name__ == "__main__":
    siren = SIREN()
    siren.run()
