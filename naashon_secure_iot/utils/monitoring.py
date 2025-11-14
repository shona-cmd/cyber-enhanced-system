"""
Monitoring and Logging utilities for NaashonSecureIoT.

Implements structured logging, SIEM integration, alerting, and audit trails.
"""

import os
import logging
import logging.handlers
import json
import time
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
import threading
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests
import hashlib
import hmac

logger = logging.getLogger(__name__)

class SecureLogger:
    """Enhanced logging with encryption and integrity verification."""

    def __init__(self, config):
        self.config = config
        self.log_queue = []
        self.setup_loggers()

    def setup_loggers(self):
        """Setup different loggers for various components."""
        # Main application logger
        self.app_logger = logging.getLogger('naashon.app')
        self.app_logger.setLevel(getattr(logging, self.config.log_level))

        # Security events logger
        self.security_logger = logging.getLogger('naashon.security')
        self.security_logger.setLevel(logging.INFO)

        # Audit logger
        self.audit_logger = logging.getLogger('naashon.audit')
        self.audit_logger.setLevel(logging.INFO)

        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(self._get_formatter())
        self.app_logger.addHandler(console_handler)

        # File handlers with rotation
        if not os.path.exists('logs'):
            os.makedirs('logs')

        # Application logs
        app_file_handler = logging.handlers.RotatingFileHandler(
            'logs/app.log', maxBytes=10*1024*1024, backupCount=5
        )
        app_file_handler.setFormatter(self._get_formatter())
        self.app_logger.addHandler(app_file_handler)

        # Security logs
        security_file_handler = logging.handlers.RotatingFileHandler(
            'logs/security.log', maxBytes=10*1024*1024, backupCount=10
        )
        security_file_handler.setFormatter(self._get_formatter())
        self.security_logger.addHandler(security_file_handler)

        # Audit logs
        audit_file_handler = logging.handlers.RotatingFileHandler(
            'logs/audit.log', maxBytes=10*1024*1024, backupCount=10
        )
        audit_file_handler.setFormatter(self._get_formatter())
        self.audit_logger.addHandler(audit_file_handler)

    def _get_formatter(self):
        """Get log formatter with structured format."""
        return logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s - %(extra)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

    def log_security_event(self, event_type: str, details: Dict[str, Any],
                          severity: str = 'info', user: str = None):
        """Log security-related events."""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'event_type': event_type,
            'severity': severity,
            'user': user,
            'details': details,
            'source_ip': getattr(threading.current_thread(), 'client_ip', None)
        }

        if self.config.log_encryption_enabled:
            log_entry = self._encrypt_log_entry(log_entry)

        extra = {'extra': json.dumps(log_entry)}
        if severity == 'critical':
            self.security_logger.critical(f"Security event: {event_type}", extra=extra)
        elif severity == 'error':
            self.security_logger.error(f"Security event: {event_type}", extra=extra)
        elif severity == 'warning':
            self.security_logger.warning(f"Security event: {event_type}", extra=extra)
        else:
            self.security_logger.info(f"Security event: {event_type}", extra=extra)

    def log_audit_event(self, action: str, resource: str, user: str,
                       result: str, details: Dict[str, Any] = None):
        """Log audit events for compliance."""
        audit_entry = {
            'timestamp': datetime.now().isoformat(),
            'action': action,
            'resource': resource,
            'user': user,
            'result': result,
            'details': details or {},
            'session_id': getattr(threading.current_thread(), 'session_id', None)
        }

        if self.config.audit_log_enabled:
            extra = {'extra': json.dumps(audit_entry)}
            self.audit_logger.info(f"Audit: {action} on {resource} by {user}", extra=extra)

    def _encrypt_log_entry(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """Encrypt sensitive log data."""
        # Placeholder for log encryption
        # In production, would use encryption utilities
        return entry


class AlertingSystem:
    """Real-time alerting system for security events."""

    def __init__(self, config):
        self.config = config
        self.alert_rules = self.load_alert_rules()
        self.active_alerts = []
        self.notification_channels = {
            'email': self._send_email_alert,
            'webhook': self._send_webhook_alert,
            'log': self._log_alert
        }

    def load_alert_rules(self) -> List[Dict[str, Any]]:
        """Load alerting rules."""
        return [
            {
                'name': 'Failed Login Attempts',
                'condition': {'event_type': 'failed_login', 'count': 5, 'time_window': 300},
                'severity': 'medium',
                'channels': ['email', 'log'],
                'enabled': True
            },
            {
                'name': 'Suspicious Activity',
                'condition': {'event_type': 'anomaly_detected', 'severity': 'high'},
                'severity': 'high',
                'channels': ['email', 'webhook'],
                'enabled': True
            },
            {
                'name': 'Device Offline',
                'condition': {'event_type': 'device_offline', 'duration': 3600},
                'severity': 'low',
                'channels': ['log'],
                'enabled': True
            }
        ]

    def process_event(self, event: Dict[str, Any]):
        """Process security event and trigger alerts if needed."""
        for rule in self.alert_rules:
            if not rule.get('enabled', False):
                continue

            if self._matches_rule(event, rule):
                self._trigger_alert(event, rule)

    def _matches_rule(self, event: Dict[str, Any], rule: Dict[str, Any]) -> bool:
        """Check if event matches alert rule."""
        condition = rule['condition']

        # Simple condition matching
        for key, value in condition.items():
            if key == 'count' or key == 'time_window' or key == 'duration':
                continue  # Skip threshold conditions for now
            if event.get(key) != value:
                return False

        return True

    def _trigger_alert(self, event: Dict[str, Any], rule: Dict[str, Any]):
        """Trigger alert for matched rule."""
        alert = {
            'id': f"alert_{int(time.time())}_{hash(str(event)) % 1000}",
            'rule_name': rule['name'],
            'severity': rule['severity'],
            'event': event,
            'timestamp': datetime.now().isoformat(),
            'status': 'active'
        }

        self.active_alerts.append(alert)

        # Send notifications
        for channel in rule.get('channels', []):
            if channel in self.notification_channels:
                try:
                    self.notification_channels[channel](alert)
                except Exception as e:
                    logger.error(f"Failed to send alert via {channel}: {e}")

        logger.warning(f"Alert triggered: {rule['name']} - {alert['id']}")

    def _send_email_alert(self, alert: Dict[str, Any]):
        """Send alert via email."""
        if not hasattr(self.config, 'alert_email_smtp') or not self.config.alert_email_smtp:
            return

        msg = MIMEMultipart()
        msg['From'] = self.config.alert_email_from
        msg['To'] = self.config.alert_email_to
        msg['Subject'] = f"Security Alert: {alert['rule_name']}"

        body = f"""
        Security Alert Details:
        Rule: {alert['rule_name']}
        Severity: {alert['severity']}
        Time: {alert['timestamp']}
        Event: {json.dumps(alert['event'], indent=2)}
        """
        msg.attach(MIMEText(body, 'plain'))

        try:
            server = smtplib.SMTP(self.config.alert_email_smtp, self.config.alert_email_port)
            server.starttls()
            server.login(self.config.alert_email_user, self.config.alert_email_password)
            server.send_message(msg)
            server.quit()
        except Exception as e:
            logger.error(f"Email alert failed: {e}")

    def _send_webhook_alert(self, alert: Dict[str, Any]):
        """Send alert via webhook."""
        webhook_url = getattr(self.config, 'alert_webhook_url', None)
        if not webhook_url:
            return

        try:
            response = requests.post(webhook_url, json=alert, timeout=5)
            response.raise_for_status()
        except Exception as e:
            logger.error(f"Webhook alert failed: {e}")

    def _log_alert(self, alert: Dict[str, Any]):
        """Log alert to file."""
        logger.warning(f"ALERT: {json.dumps(alert)}")

    def get_active_alerts(self) -> List[Dict[str, Any]]:
        """Get list of active alerts."""
        return self.active_alerts

    def resolve_alert(self, alert_id: str):
        """Resolve an active alert."""
        for alert in self.active_alerts:
            if alert['id'] == alert_id:
                alert['status'] = 'resolved'
                alert['resolved_at'] = datetime.now().isoformat()
                logger.info(f"Alert resolved: {alert_id}")
                break


class SIEMIntegration:
    """SIEM system integration for centralized logging."""

    def __init__(self, config):
        self.config = config
        self.siem_endpoint = getattr(self.config, 'siem_endpoint', None)
        self.api_key = getattr(self.config, 'siem_api_key', None)
        self.batch_size = 100
        self.event_buffer = []

    def send_event(self, event: Dict[str, Any]):
        """Send security event to SIEM."""
        if not self.config.siem_integration_enabled or not self.siem_endpoint:
            return

        self.event_buffer.append(event)

        # Send in batches
        if len(self.event_buffer) >= self.batch_size:
            self._flush_events()

    def _flush_events(self):
        """Flush buffered events to SIEM."""
        if not self.event_buffer:
            return

        try:
            headers = {'Authorization': f'Bearer {self.api_key}'} if self.api_key else {}
            response = requests.post(
                self.siem_endpoint,
                json={'events': self.event_buffer},
                headers=headers,
                timeout=10
            )
            response.raise_for_status()
            logger.debug(f"Sent {len(self.event_buffer)} events to SIEM")
            self.event_buffer.clear()
        except Exception as e:
            logger.error(f"SIEM integration failed: {e}")

    def flush_remaining_events(self):
        """Flush any remaining events in buffer."""
        self._flush_events()


class AuditTrail:
    """Audit trail for compliance and forensic analysis."""

    def __init__(self, config):
        self.config = config
        self.audit_log = []

    def record_action(self, action: str, actor: str, target: str,
                     result: str, metadata: Dict[str, Any] = None):
        """Record an auditable action."""
        audit_entry = {
            'timestamp': datetime.now().isoformat(),
            'action': action,
            'actor': actor,
            'target': target,
            'result': result,
            'metadata': metadata or {},
            'integrity_hash': self._calculate_integrity_hash(action, actor, target, result)
        }

        self.audit_log.append(audit_entry)

        # Log to audit logger
        logger.info(f"AUDIT: {action} by {actor} on {target} - {result}")

    def _calculate_integrity_hash(self, action: str, actor: str, target: str, result: str) -> str:
        """Calculate integrity hash for audit entry."""
        data = f"{action}{actor}{target}{result}{datetime.now().isoformat()}"
        return hashlib.sha256(data.encode()).hexdigest()

    def verify_integrity(self) -> bool:
        """Verify integrity of audit log."""
        for entry in self.audit_log:
            expected_hash = self._calculate_integrity_hash(
                entry['action'], entry['actor'], entry['target'], entry['result']
            )
            if entry.get('integrity_hash') != expected_hash:
                return False
        return True

    def get_audit_log(self, start_date: datetime = None, end_date: datetime = None,
                     actor: str = None, action: str = None) -> List[Dict[str, Any]]:
        """Query audit log with filters."""
        filtered_log = self.audit_log

        if start_date:
            filtered_log = [e for e in filtered_log if datetime.fromisoformat(e['timestamp']) >= start_date]
        if end_date:
            filtered_log = [e for e in filtered_log if datetime.fromisoformat(e['timestamp']) <= end_date]
        if actor:
            filtered_log = [e for e in filtered_log if e['actor'] == actor]
        if action:
            filtered_log = [e for e in filtered_log if e['action'] == action]

        return filtered_log

    def export_audit_log(self, format: str = 'json') -> str:
        """Export audit log in specified format."""
        if format == 'json':
            return json.dumps(self.audit_log, indent=2)
        elif format == 'csv':
            # Simple CSV export
            if not self.audit_log:
                return ""
            headers = list(self.audit_log[0].keys())
            csv_lines = [','.join(headers)]
            for entry in self.audit_log:
                csv_lines.append(','.join(str(entry.get(h, '')) for h in headers))
            return '\n'.join(csv_lines)
        else:
            raise ValueError(f"Unsupported export format: {format}")


class MonitoringManager:
    """Central manager for monitoring and logging components."""

    def __init__(self, config):
        self.config = config
        self.logger = SecureLogger(config)
        self.alerting = AlertingSystem(config)
        self.siem = SIEMIntegration(config)
        self.audit = AuditTrail(config)
        self.metrics = {}

    def initialize(self):
        """Initialize monitoring components."""
        logger.info("Initializing monitoring components")

        # Start background tasks
        self._start_background_tasks()

        logger.info("Monitoring components initialized")

    def _start_background_tasks(self):
        """Start background monitoring tasks."""
        # Cleanup task
        cleanup_thread = threading.Thread(target=self._cleanup_task, daemon=True)
        cleanup_thread.start()

        # Metrics collection task
        metrics_thread = threading.Thread(target=self._metrics_task, daemon=True)
        metrics_thread.start()

    def _cleanup_task(self):
        """Background cleanup task."""
        while True:
            time.sleep(300)  # Run every 5 minutes
            try:
                # Cleanup old alerts (keep last 24 hours)
                cutoff = datetime.now() - timedelta(hours=24)
                self.alerting.active_alerts = [
                    alert for alert in self.alerting.active_alerts
                    if datetime.fromisoformat(alert['timestamp']) > cutoff
                ]

                # Flush SIEM events
                self.siem.flush_remaining_events()

            except Exception as e:
                logger.error(f"Cleanup task error: {e}")

    def _metrics_task(self):
        """Collect system metrics."""
        while True:
            time.sleep(60)  # Run every minute
            try:
                self.metrics.update({
                    'timestamp': datetime.now().isoformat(),
                    'active_alerts': len(self.alerting.active_alerts),
                    'audit_entries': len(self.audit.audit_log),
                    'siem_buffer_size': len(self.siem.event_buffer)
                })
            except Exception as e:
                logger.error(f"Metrics collection error: {e}")

    def log_security_event(self, event_type: str, details: Dict[str, Any],
                          severity: str = 'info', user: str = None):
        """Log security event and check for alerts."""
        self.logger.log_security_event(event_type, details, severity, user)
        self.alerting.process_event({
            'event_type': event_type,
            'details': details,
            'severity': severity,
            'user': user
        })
        self.siem.send_event({
            'event_type': event_type,
            'details': details,
            'severity': severity,
            'user': user,
            'timestamp': datetime.now().isoformat()
        })

    def record_audit_action(self, action: str, actor: str, target: str,
                           result: str, metadata: Dict[str, Any] = None):
        """Record audit action."""
        self.audit.record_action(action, actor, target, result, metadata)
        self.logger.log_audit_event(action, target, actor, result, metadata)

    def get_status(self) -> Dict[str, Any]:
        """Get status of monitoring components."""
        return {
            'logging': {
                'enabled': True,
                'encryption_enabled': self.config.log_encryption_enabled
            },
            'alerting': {
                'enabled': self.config.alerting_enabled,
                'active_alerts': len(self.alerting.active_alerts),
                'rules_count': len(self.alerting.alert_rules)
            },
            'siem': {
                'enabled': self.config.siem_integration_enabled,
                'buffer_size': len(self.siem.event_buffer)
            },
            'audit': {
                'enabled': self.config.audit_log_enabled,
                'entries_count': len(self.audit.audit_log),
                'integrity_verified': self.audit.verify_integrity()
            },
            'metrics': self.metrics
        }
