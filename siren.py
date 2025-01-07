#!/usr/bin/env python3

"""
SIREN - Security Infrastructure for Research and Education Network
Enhanced Python Application for Vulnerability Management and Monitoring
Version: 2.0
"""

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
from typing import Dict, List, Optional, Union, Tuple, Any
from dataclasses import dataclass, asdict
import time
import queue
import re
import ipaddress
import traceback
from functools import wraps

# Third-party imports with proper error handling
try:
    from flask import Flask, request, render_template_string, send_file, jsonify, Response
    import paramiko
    import psutil
    from prometheus_client import Counter, Gauge, start_http_server
    from colorama import init, Fore, Style
except ImportError as e:
    print(f"Error: Required package not found: {e}")
    print("Please install required packages: pip install flask paramiko psutil prometheus_client colorama")
    sys.exit(1)

# Initialize colorama
init()

@dataclass
class VulnerabilityConfig:
    """Configuration for vulnerability types with enhanced tracking"""
    name: str
    enabled: bool
    risk_level: str
    description: str
    mitigation: str
    detection_patterns: List[str]
    max_attempts: int
    cooldown_period: int
    last_triggered: Optional[datetime] = None
    attempt_count: int = 0

    def to_dict(self) -> dict:
        """Convert configuration to dictionary format"""
        return asdict(self)

    def reset_attempts(self) -> None:
        """Reset attempt counter and last triggered timestamp"""
        self.attempt_count = 0
        self.last_triggered = None

class SecurityEvent:
    """Enhanced security event tracking"""
    def __init__(
        self,
        event_type: str,
        severity: str,
        details: dict,
        source_ip: Optional[str] = None,
        user_agent: Optional[str] = None
    ):
        self.timestamp = datetime.now()
        self.event_type = event_type
        self.severity = severity
        self.details = details
        self.event_id = secrets.token_hex(8)
        self.source_ip = source_ip
        self.user_agent = user_agent

    def to_dict(self) -> dict:
        """Convert event to dictionary format with enhanced details"""
        return {
            'event_id': self.event_id,
            'timestamp': self.timestamp.isoformat(),
            'type': self.event_type,
            'severity': self.severity,
            'details': self.details,
            'source_ip': self.source_ip,
            'user_agent': self.user_agent,
            'metadata': {
                'hostname': socket.gethostname(),
                'pid': os.getpid()
            }
        }

class SecurityMonitor:
    """Enhanced security monitoring and alerting system"""
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.alert_queue: queue.Queue = queue.Queue()
        self.events: queue.Queue = queue.Queue(maxsize=1000)
        self.baseline_stats: Dict[str, Any] = {}
        self.anomaly_threshold = 2.0
        self._setup_metrics()
        self._init_baseline()

    def _setup_metrics(self) -> None:
        """Initialize Prometheus metrics"""
        self.metrics = {
            'security_events': Counter(
                'siren_security_events_total',
                'Total security events by type and severity',
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
            ),
            'vulnerability_attempts': Counter(
                'siren_vulnerability_attempts_total',
                'Vulnerability exploitation attempts',
                ['vulnerability_type', 'success']
            )
        }

    def _init_baseline(self) -> None:
        """Initialize system baseline statistics"""
        try:
            self.baseline_stats = {
                'cpu_usage': psutil.cpu_percent(interval=1),
                'memory_usage': psutil.virtual_memory().percent,
                'disk_usage': psutil.disk_usage('/').percent,
                'network_connections': len(psutil.net_connections()),
                'running_processes': len(psutil.process_iter())
            }
            self.logger.info(f"Baseline statistics initialized: {self.baseline_stats}")
        except Exception as e:
            self.logger.error(f"Failed to initialize baseline statistics: {e}")
            self.baseline_stats = {}

    def update_metrics(self) -> None:
        """Update Prometheus metrics with current system state"""
        try:
            self.metrics['system_load'].set(os.getloadavg()[0])
            self.metrics['memory_usage'].set(psutil.virtual_memory().used)
            self.metrics['active_connections'].set(
                len(psutil.net_connections())
            )
        except Exception as e:
            self.logger.error(f"Failed to update metrics: {e}")

    def record_event(self, event: SecurityEvent) -> None:
        """Record and analyze security events with enhanced tracking"""
        try:
            # Update Prometheus metrics
            self.metrics['security_events'].labels(
                event_type=event.event_type,
                severity=event.severity
            ).inc()

            # Store event with overflow protection
            try:
                self.events.put_nowait(event)
            except queue.Full:
                # Remove oldest event if queue is full
                self.events.get_nowait()
                self.events.put_nowait(event)

            # Log event details
            self.logger.warning(
                f"Security Event: {event.to_dict()}",
                extra={'event_id': event.event_id}
            )

            # Check for anomalies
            if self._check_anomaly(event):
                self._trigger_alert(event)

        except Exception as e:
            self.logger.error(f"Failed to record security event: {e}")
            self.logger.debug(traceback.format_exc())

    def _check_anomaly(self, event: SecurityEvent) -> bool:
        """Enhanced anomaly detection with pattern matching"""
        try:
            # Check event frequency
            event_count = sum(
                1 for e in list(self.events.queue)
                if e.event_type == event.event_type
                and (datetime.now() - e.timestamp).total_seconds() < 3600
            )

            # Check for known attack patterns
            if self._match_attack_patterns(event):
                return True

            # Check for system resource anomalies
            if self._check_resource_anomalies():
                return True

            # Check event frequency threshold
            return event_count > self.anomaly_threshold

        except Exception as e:
            self.logger.error(f"Anomaly check failed: {e}")
            return False

    def _match_attack_patterns(self, event: SecurityEvent) -> bool:
        """Match events against known attack patterns"""
        # Add your attack pattern matching logic here
        return False

    def _check_resource_anomalies(self) -> bool:
        """Check for system resource anomalies"""
        try:
            current_stats = {
                'cpu_usage': psutil.cpu_percent(),
                'memory_usage': psutil.virtual_memory().percent,
                'disk_usage': psutil.disk_usage('/').percent,
                'network_connections': len(psutil.net_connections())
            }

            for metric, value in current_stats.items():
                if metric in self.baseline_stats:
                    if value > self.baseline_stats[metric] * self.anomaly_threshold:
                        self.logger.warning(
                            f"Resource anomaly detected: {metric} "
                            f"(current: {value}, baseline: {self.baseline_stats[metric]})"
                        )
                        return True

            return False

        except Exception as e:
            self.logger.error(f"Resource anomaly check failed: {e}")
            return False

    def _trigger_alert(self, event: SecurityEvent) -> None:
        """Handle security alerts with enhanced notification options"""
        try:
            alert = {
                'timestamp': datetime.now().isoformat(),
                'event': event.to_dict(),
                'recommendations': self._get_recommendations(event),
                'system_state': self._get_system_state()
            }

            # Add alert to queue
            self.alert_queue.put(alert)

            # Log alert
            self.logger.error(f"Security Alert Triggered: {alert}")

            # Execute alert actions
            self._execute_alert_actions(alert)

        except Exception as e:
            self.logger.error(f"Failed to trigger alert: {e}")

    def _get_system_state(self) -> dict:
        """Capture current system state for alert context"""
        try:
            return {
                'cpu_usage': psutil.cpu_percent(interval=1),
                'memory_usage': psutil.virtual_memory().percent,
                'disk_usage': psutil.disk_usage('/').percent,
                'network_connections': len(psutil.net_connections()),
                'load_average': os.getloadavg(),
                'process_count': len(list(psutil.process_iter())),
                'open_files': len(psutil.Process().open_files()),
                'network_io': psutil.net_io_counters()._asdict()
            }
        except Exception as e:
            self.logger.error(f"Failed to get system state: {e}")
            return {}

    def _execute_alert_actions(self, alert: dict) -> None:
        """Execute configured alert actions"""
        try:
            # Custom alert handlers could be added here
            pass
        except Exception as e:
            self.logger.error(f"Failed to execute alert actions: {e}")

class SIREN:
    """Enhanced SIREN vulnerability lab manager"""
    def __init__(self):
        """Initialize SIREN with comprehensive security controls"""
        self.start_time = datetime.now()
        self._setup_logging()
        self._init_security()
        self.config = self._load_config()
        self.monitor = SecurityMonitor(self.logger)
        self._setup_paths()
        self._init_encryption()
        self._setup_metrics_server()
        self.vulnerability_configs = self._load_vulnerability_configs()
        self.app = self._create_flask_app()

    def _setup_logging(self) -> None:
        """Configure comprehensive logging system"""
        log_config = {
            'version': 1,
            'disable_existing_loggers': False,
            'formatters': {
                'detailed': {
                    'format': '%(asctime)s [%(name)s] %(levelname)s [%(pathname)s:%(lineno)d] %(message)s'
                }
            },
            'handlers': {
                'file': {
                    'class': 'logging.handlers.RotatingFileHandler',
                    'filename': '/var/log/siren/siren.log',
                    'maxBytes': 10485760,  # 10MB
                    'backupCount': 5,
                    'formatter': 'detailed',
                    'level': 'DEBUG'
                },
                'console': {
                    'class': 'logging.StreamHandler',
                    'formatter': 'detailed',
                    'level': 'INFO'
                }
            },
            'loggers': {
                'siren': {
                    'handlers': ['file', 'console'],
                    'level': 'DEBUG',
                    'propagate': True
                }
            }
        }
        logging.config.dictConfig(log_config)
        self.logger = logging.getLogger('siren')

    def _init_security(self) -> None:
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
        
        # Initialize security controls
        self._setup_ip_filtering()
        self._init_file_monitoring()
        self._setup_rate_limiting()

    def _setup_ip_filtering(self) -> None:
        """Setup IP filtering and blocking mechanism"""
        self.ip_blacklist = set()
        self.ip_whitelist = set()
        self.ip_tracking: Dict[str, Dict] = {}
        
        # Load IP lists from configuration
        try:
            with open('/opt/siren/config/ip_blacklist.txt', 'r') as f:
                self.ip_blacklist.update(line.strip() for line in f)
        except FileNotFoundError:
            self.logger.warning("IP blacklist file not found")

    def _init_file_monitoring(self) -> None:
        """Initialize file integrity monitoring"""
        self.monitored_files: Dict[str, str] = {}
        self.file_monitor_thread = threading.Thread(
            target=self._file_monitor_loop,
            daemon=True
        )
        self.file_monitor_thread.start()

    def _file_monitor_loop(self) -> None:
        """Continuous file integrity monitoring loop"""
        while True:
            try:
                self._check_file_integrity()
                time.sleep(60)  # Check every minute
            except Exception as e:
                self.logger.error(f"File monitoring error: {e}")

    def _check_file_integrity(self) -> None:
        """Check integrity of monitored files"""
        for filepath, stored_hash in self.monitored_files.items():
            try:
                current_hash = self._calculate_file_hash(filepath)
                if current_hash != stored_hash:
                    self.monitor.record_event(
                        SecurityEvent(
                            'file_modification',
                            'high',
                            {
                                'file': filepath,
                                'original_hash': stored_hash,
                                'current_hash': current_hash
                            }
                        )
                    )
                    self.monitored_files[filepath] = current_hash
            except Exception as e:
                self.logger.error(f"File integrity check failed for {filepath}: {e}")

    @staticmethod
    def _calculate_file_hash(filepath: str) -> str:
        """Calculate SHA-256 hash of a file"""
        sha256_hash = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            raise RuntimeError(f"Failed to calculate file hash: {e}")

    def _setup_rate_limiting(self) -> None:
        """Setup rate limiting for API endpoints"""
        self.rate_limits: Dict[str, Dict] = {}
        self.rate_limit_cleanup_thread = threading.Thread(
            target=self._cleanup_rate_limits,
            daemon=True
        )
        self.rate_limit_cleanup_thread.start()

    def _cleanup_rate_limits(self) -> None:
        """Clean up expired rate limit entries"""
        while True:
            try:
                current_time = time.time()
                for ip in list(self.rate_limits.keys()):
                    if current_time - self.rate_limits[ip]['last_reset'] > 3600:
                        del self.rate_limits[ip]
                time.sleep(300)  # Clean up every 5 minutes
            except Exception as e:
                self.logger.error(f"Rate limit cleanup error: {e}")

    def run(self) -> None:
        """Run the SIREN application with comprehensive monitoring"""
        try:
            # Start monitoring threads
            self._start_monitoring_threads()
            
            # Configure SSL context if enabled
            ssl_context = self._setup_ssl() if self.config['USE_SSL'] else None
            
            # Start the Flask application
            self.app.run(
                host=self.config['HOST'],
                port=self.config['PORT'],
                ssl_context=ssl_context,
                threaded=True
            )
        except Exception as e:
            self.logger.critical(f"Application startup failed: {e}")
            sys.exit(1)
        finally:
            self._cleanup()

    def _start_monitoring_threads(self) -> None:
        """Start all monitoring threads"""
        monitoring_threads = [
            threading.Thread(target=self._system_monitor_loop, daemon=True),
            threading.Thread(target=self._network_monitor_loop, daemon=True),
            threading.Thread(target=self._security_event_processor, daemon=True)
        ]
        
        for thread in monitoring_threads:
            thread.start()

    def _cleanup(self) -> None:
        """Perform cleanup operations"""
        try:
            # Save current state
            self._save_state()
            
            # Clean up temporary files
            self._cleanup_temp_files()
            
            # Close network connections
            self._close_connections()
            
            self.logger.info("Cleanup completed successfully")
        except Exception as e:
            self.logger.error(f"Cleanup failed: {e}")

if __name__ == "__main__":
    try:
        siren = SIREN()
        siren.run()
    except KeyboardInterrupt:
        print("\nShutting down SIREN...")
        sys.exit(0)
    except Exception as e:
        print(f"Fatal error: {e}")
        logging.error(f"Fatal error: {e}")
        sys.exit(1)
