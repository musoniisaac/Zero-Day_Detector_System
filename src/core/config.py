#!/usr/bin/env python3
"""
Configuration Manager
Handles loading and validation of system configuration
"""

import yaml
import logging
from typing import Dict, Any
from pathlib import Path


class ConfigManager:
    """Manages system configuration"""
    
    def __init__(self, config_path: str):
        self.config_path = Path(config_path)
        self.logger = logging.getLogger(__name__)
    
    def load_config(self) -> Dict[str, Any]:
        """Load configuration from file"""
        if not self.config_path.exists():
            self.logger.warning(f"Config file not found: {self.config_path}")
            return self._get_default_config()
        
        try:
            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f)
            
            # Validate configuration
            self._validate_config(config)
            
            self.logger.info(f"Configuration loaded from {self.config_path}")
            return config
            
        except Exception as e:
            self.logger.error(f"Error loading config: {e}")
            self.logger.info("Using default configuration")
            return self._get_default_config()
    
    def _validate_config(self, config: Dict[str, Any]):
        """Validate configuration structure"""
        required_sections = ['system', 'data_sources', 'detection', 'alerts']
        
        for section in required_sections:
            if section not in config:
                raise ValueError(f"Missing required configuration section: {section}")
        
        # Validate system settings
        system = config['system']
        if system.get('max_cpu_usage', 5.0) > 50.0:
            self.logger.warning("High CPU usage limit configured")
        
        if system.get('max_memory_mb', 512) > 2048:
            self.logger.warning("High memory usage limit configured")
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration"""
        return {
            'system': {
                'max_cpu_usage': 5.0,
                'max_memory_mb': 512,
                'worker_threads': 4,
                'queue_size': 10000,
                'log_retention_days': 30,
                'alert_retention_days': 90
            },
            'data_sources': {
                'system_logs': {
                    'enabled': True,
                    'paths': [
                        '/var/log/auth.log',
                        '/var/log/syslog',
                        '/var/log/apache2/access.log',
                        '/var/log/nginx/access.log'
                    ],
                    'formats': ['syslog', 'apache', 'nginx'],
                    'poll_interval': 1.0
                },
                'network': {
                    'enabled': True,
                    'interfaces': ['eth0', 'wlan0'],
                    'capture_filter': 'not broadcast and not multicast',
                    'protocols': ['tcp', 'udp', 'icmp'],
                    'buffer_size': 16777216  # 16MB
                }
            },
            'detection': {
                'baseline_window_hours': 168,  # 7 days
                'anomaly_sensitivity': 'medium',
                'min_baseline_samples': 100,
                'rule_update_interval': 300
            },
            'alerts': {
                'max_history': 10000,
                'rate_limiting': {
                    'enabled': True,
                    'max_alerts_per_window': 10,
                    'window_seconds': 300
                },
                'severity_routing': {
                    'critical': ['email', 'syslog', 'file'],
                    'high': ['email', 'syslog', 'file'],
                    'medium': ['syslog', 'file'],
                    'low': ['file']
                },
                'email': {
                    'enabled': False,
                    'smtp_server': 'localhost',
                    'smtp_port': 587,
                    'use_tls': True,
                    'from_address': 'zdd@localhost',
                    'to_addresses': ['admin@localhost']
                },
                'syslog': {
                    'enabled': True,
                    'facility': 'security'
                },
                'file': {
                    'enabled': True,
                    'path': '/var/log/zdd/alerts.log'
                },
                'webhook': {
                    'enabled': False,
                    'url': '',
                    'timeout': 10
                }
            }
        }