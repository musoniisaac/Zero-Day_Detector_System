#!/usr/bin/env python3
"""
Alert Manager
Handles alert processing, routing, and notifications
"""

import time
import json
import logging
import smtplib
import subprocess
from typing import Dict, List, Any, Optional
from email.mime.text import MimeText
from email.mime.multipart import MimeMultipart
from pathlib import Path

from .rule_engine import Alert


class AlertManager:
    """Manages alert processing and notifications"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Alert storage
        self.alert_history = []
        self.max_history = config.get('max_history', 10000)
        
        # Notification channels
        self.notification_channels = self._initialize_channels()
        
        # Rate limiting
        self.rate_limits = {}
        
        self.logger.info("Alert manager initialized")
    
    def _initialize_channels(self) -> Dict[str, Any]:
        """Initialize notification channels"""
        channels = {}
        
        # Email notifications
        if self.config.get('email', {}).get('enabled', False):
            channels['email'] = self.config['email']
        
        # Syslog notifications
        if self.config.get('syslog', {}).get('enabled', True):
            channels['syslog'] = self.config.get('syslog', {})
        
        # File logging
        if self.config.get('file', {}).get('enabled', True):
            channels['file'] = self.config.get('file', {})
        
        # Webhook notifications
        if self.config.get('webhook', {}).get('enabled', False):
            channels['webhook'] = self.config['webhook']
        
        self.logger.info(f"Initialized notification channels: {list(channels.keys())}")
        return channels
    
    def process_alert(self, alert: Alert):
        """Process and route an alert"""
        try:
            # Add to history
            self.alert_history.append(alert)
            if len(self.alert_history) > self.max_history:
                self.alert_history.pop(0)
            
            # Check rate limiting
            if self._is_rate_limited(alert):
                self.logger.debug(f"Alert {alert.alert_id} rate limited")
                return
            
            # Route to appropriate channels based on severity
            channels = self._get_channels_for_severity(alert.severity)
            
            for channel in channels:
                self._send_notification(alert, channel)
            
            self.logger.info(f"Processed alert {alert.alert_id} ({alert.severity})")
            
        except Exception as e:
            self.logger.error(f"Error processing alert {alert.alert_id}: {e}")
    
    def _is_rate_limited(self, alert: Alert) -> bool:
        """Check if alert should be rate limited"""
        rate_limit_config = self.config.get('rate_limiting', {})
        if not rate_limit_config.get('enabled', True):
            return False
        
        # Create rate limit key
        key = f"{alert.rule_id}_{alert.source.get('ip_address', 'unknown')}"
        current_time = time.time()
        
        # Clean old entries
        if key in self.rate_limits:
            self.rate_limits[key] = [
                t for t in self.rate_limits[key] 
                if current_time - t < rate_limit_config.get('window_seconds', 300)
            ]
        else:
            self.rate_limits[key] = []
        
        # Check limit
        max_alerts = rate_limit_config.get('max_alerts_per_window', 10)
        if len(self.rate_limits[key]) >= max_alerts:
            return True
        
        # Add current alert
        self.rate_limits[key].append(current_time)
        return False
    
    def _get_channels_for_severity(self, severity: str) -> List[str]:
        """Get notification channels for alert severity"""
        severity_config = self.config.get('severity_routing', {})
        
        default_channels = ['syslog', 'file']
        
        if severity == 'critical':
            return severity_config.get('critical', ['email', 'syslog', 'file'])
        elif severity == 'high':
            return severity_config.get('high', ['email', 'syslog', 'file'])
        elif severity == 'medium':
            return severity_config.get('medium', ['syslog', 'file'])
        else:  # low
            return severity_config.get('low', ['file'])
    
    def _send_notification(self, alert: Alert, channel: str):
        """Send notification to specific channel"""
        try:
            if channel == 'email':
                self._send_email_notification(alert)
            elif channel == 'syslog':
                self._send_syslog_notification(alert)
            elif channel == 'file':
                self._send_file_notification(alert)
            elif channel == 'webhook':
                self._send_webhook_notification(alert)
            else:
                self.logger.warning(f"Unknown notification channel: {channel}")
                
        except Exception as e:
            self.logger.error(f"Error sending notification to {channel}: {e}")
    
    def _send_email_notification(self, alert: Alert):
        """Send email notification"""
        if 'email' not in self.notification_channels:
            return
        
        config = self.notification_channels['email']
        
        # Create message
        msg = MimeMultipart()
        msg['From'] = config.get('from_address', 'zdd@localhost')
        msg['To'] = ', '.join(config.get('to_addresses', []))
        msg['Subject'] = f"[ZDD {alert.severity.upper()}] {alert.rule_name}"
        
        # Create email body
        body = self._format_alert_email(alert)
        msg.attach(MimeText(body, 'plain'))
        
        # Send email
        smtp_server = config.get('smtp_server', 'localhost')
        smtp_port = config.get('smtp_port', 587)
        
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            if config.get('use_tls', True):
                server.starttls()
            
            username = config.get('username')
            password = config.get('password')
            if username and password:
                server.login(username, password)
            
            server.send_message(msg)
    
    def _send_syslog_notification(self, alert: Alert):
        """Send syslog notification"""
        import syslog
        
        # Map severity to syslog priority
        priority_map = {
            'critical': syslog.LOG_CRIT,
            'high': syslog.LOG_ERR,
            'medium': syslog.LOG_WARNING,
            'low': syslog.LOG_INFO
        }
        
        priority = priority_map.get(alert.severity, syslog.LOG_INFO)
        
        # Format message
        message = f"ZDD Alert: {alert.rule_name} | Source: {alert.source.get('ip_address', 'unknown')} | Details: {json.dumps(alert.details)}"
        
        # Send to syslog
        syslog.openlog("zdd-detector", syslog.LOG_PID, syslog.LOG_SECURITY)
        syslog.syslog(priority, message)
        syslog.closelog()
    
    def _send_file_notification(self, alert: Alert):
        """Send file notification"""
        config = self.notification_channels.get('file', {})
        log_file = config.get('path', '/var/log/zdd/alerts.log')
        
        # Ensure directory exists
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        
        # Format alert as JSON
        alert_data = {
            'timestamp': alert.timestamp,
            'alert_id': alert.alert_id,
            'rule_id': alert.rule_id,
            'rule_name': alert.rule_name,
            'severity': alert.severity,
            'source': alert.source,
            'details': alert.details,
            'evidence': alert.evidence
        }
        
        # Write to file
        with open(log_file, 'a') as f:
            f.write(json.dumps(alert_data) + '\n')
    
    def _send_webhook_notification(self, alert: Alert):
        """Send webhook notification"""
        import requests
        
        if 'webhook' not in self.notification_channels:
            return
        
        config = self.notification_channels['webhook']
        url = config.get('url')
        
        if not url:
            return
        
        # Prepare payload
        payload = {
            'timestamp': alert.timestamp,
            'alert_id': alert.alert_id,
            'rule_id': alert.rule_id,
            'rule_name': alert.rule_name,
            'severity': alert.severity,
            'source': alert.source,
            'details': alert.details
        }
        
        # Send webhook
        headers = {'Content-Type': 'application/json'}
        timeout = config.get('timeout', 10)
        
        response = requests.post(url, json=payload, headers=headers, timeout=timeout)
        response.raise_for_status()
    
    def _format_alert_email(self, alert: Alert) -> str:
        """Format alert for email notification"""
        return f"""
Zero-Day Detector Alert

Alert ID: {alert.alert_id}
Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(alert.timestamp))}
Rule: {alert.rule_name} ({alert.rule_id})
Severity: {alert.severity.upper()}

Source Information:
- IP Address: {alert.source.get('ip_address', 'unknown')}
- Event Type: {alert.source.get('event_type', 'unknown')}

Alert Details:
{json.dumps(alert.details, indent=2)}

Evidence:
{json.dumps(alert.evidence, indent=2)}

---
Zero-Day Detector System
        """.strip()
    
    def get_alert_stats(self) -> Dict[str, Any]:
        """Get alert statistics"""
        if not self.alert_history:
            return {'total_alerts': 0}
        
        # Count by severity
        severity_counts = {}
        for alert in self.alert_history:
            severity_counts[alert.severity] = severity_counts.get(alert.severity, 0) + 1
        
        # Recent alerts (last hour)
        current_time = time.time()
        recent_alerts = [
            alert for alert in self.alert_history 
            if current_time - alert.timestamp < 3600
        ]
        
        return {
            'total_alerts': len(self.alert_history),
            'recent_alerts_1h': len(recent_alerts),
            'severity_breakdown': severity_counts,
            'latest_alert': self.alert_history[-1].timestamp if self.alert_history else None
        }