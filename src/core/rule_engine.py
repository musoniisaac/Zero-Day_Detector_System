#!/usr/bin/env python3
"""
Rule Engine
Pattern-based detection using configurable rules
Created by Isaac Musoni
"""

import re
import time
import logging
from typing import Dict, List, Any, Optional
from collections import defaultdict, deque
from dataclasses import dataclass


@dataclass
class Alert:
    """Alert data structure"""
    alert_id: str
    timestamp: float
    rule_id: str
    rule_name: str
    severity: str
    source: Dict[str, Any]
    details: Dict[str, Any]
    evidence: List[Dict[str, Any]]


class Rule:
    """Individual detection rule"""
    
    def __init__(self, rule_data: Dict[str, Any]):
        self.rule_id = rule_data['rule_id']
        self.name = rule_data['name']
        self.category = rule_data.get('category', 'general')
        self.severity = rule_data.get('severity', 'medium')
        self.enabled = rule_data.get('enabled', True)
        self.conditions = rule_data.get('conditions', {})
        self.actions = rule_data.get('actions', [])
        
        # Compile regex patterns for performance
        self.compiled_patterns = {}
        self._compile_patterns()
        
        # State tracking for stateful rules
        self.state = defaultdict(lambda: deque(maxlen=1000))
    
    def _compile_patterns(self):
        """Compile regex patterns for better performance"""
        for condition_name, condition in self.conditions.items():
            if 'pattern' in condition:
                try:
                    self.compiled_patterns[condition_name] = re.compile(
                        condition['pattern'], 
                        re.IGNORECASE if condition.get('case_insensitive', True) else 0
                    )
                except re.error as e:
                    logging.getLogger(__name__).error(
                        f"Invalid regex in rule {self.rule_id}, condition {condition_name}: {e}"
                    )
    
    def evaluate(self, event) -> Optional[Alert]:
        """Evaluate event against this rule"""
        if not self.enabled:
            return None
        
        current_time = time.time()
        
        # Check all conditions
        for condition_name, condition in self.conditions.items():
            if not self._evaluate_condition(event, condition_name, condition, current_time):
                return None
        
        # All conditions matched, create alert
        return self._create_alert(event, current_time)
    
    def _evaluate_condition(self, event, condition_name: str, condition: Dict[str, Any], timestamp: float) -> bool:
        """Evaluate a single condition"""
        condition_type = condition.get('type', 'pattern_match')
        
        if condition_type == 'pattern_match':
            return self._check_pattern(event, condition_name, condition)
        elif condition_type == 'threshold':
            return self._check_threshold(event, condition_name, condition, timestamp)
        elif condition_type == 'frequency':
            return self._check_frequency(event, condition_name, condition, timestamp)
        elif condition_type == 'field_match':
            return self._check_field_match(event, condition)
        
        return False
    
    def _check_pattern(self, event, condition_name: str, condition: Dict[str, Any]) -> bool:
        """Check pattern matching condition"""
        if condition_name not in self.compiled_patterns:
            return False
        
        pattern = self.compiled_patterns[condition_name]
        field = condition.get('field', 'message')
        
        # Get field value from event
        if hasattr(event, 'data') and field in event.data:
            text = str(event.data[field])
        elif hasattr(event, field):
            text = str(getattr(event, field))
        else:
            return False
        
        return bool(pattern.search(text))
    
    def _check_threshold(self, event, condition_name: str, condition: Dict[str, Any], timestamp: float) -> bool:
        """Check threshold-based condition"""
        field = condition.get('field', 'count')
        threshold = condition.get('threshold', 0)
        
        # Get current value
        if hasattr(event, 'data') and field in event.data:
            current_value = event.data[field]
        else:
            return False
        
        return current_value > threshold
    
    def _check_frequency(self, event, condition_name: str, condition: Dict[str, Any], timestamp: float) -> bool:
        """Check frequency-based condition"""
        time_window = condition.get('time_window', 60)  # seconds
        threshold = condition.get('threshold', 10)
        key_field = condition.get('key_field', 'source_ip')
        
        # Get key for grouping
        if hasattr(event, 'data') and key_field in event.data:
            key = event.data[key_field]
        elif hasattr(event, key_field):
            key = getattr(event, key_field)
        else:
            key = 'default'
        
        # Track events for this key
        state_key = f"{condition_name}_{key}"
        self.state[state_key].append(timestamp)
        
        # Count events in time window
        window_start = timestamp - time_window
        recent_events = [t for t in self.state[state_key] if t >= window_start]
        
        return len(recent_events) >= threshold
    
    def _check_field_match(self, event, condition: Dict[str, Any]) -> bool:
        """Check field value matching"""
        field = condition.get('field')
        expected_value = condition.get('value')
        operator = condition.get('operator', 'equals')
        
        if not field or expected_value is None:
            return False
        
        # Get actual value
        if hasattr(event, 'data') and field in event.data:
            actual_value = event.data[field]
        elif hasattr(event, field):
            actual_value = getattr(event, field)
        else:
            return False
        
        # Apply operator
        if operator == 'equals':
            return actual_value == expected_value
        elif operator == 'not_equals':
            return actual_value != expected_value
        elif operator == 'greater_than':
            return actual_value > expected_value
        elif operator == 'less_than':
            return actual_value < expected_value
        elif operator == 'contains':
            return expected_value in str(actual_value)
        
        return False
    
    def _create_alert(self, event, timestamp: float) -> Alert:
        """Create alert from matched rule"""
        alert_id = f"alert_{int(timestamp)}_{self.rule_id}_{hash(str(event.data)) % 10000:04d}"
        
        return Alert(
            alert_id=alert_id,
            timestamp=timestamp,
            rule_id=self.rule_id,
            rule_name=self.name,
            severity=self.severity,
            source={
                'ip_address': getattr(event, 'source_ip', 'unknown'),
                'event_type': getattr(event, 'event_type', 'unknown'),
                'source': getattr(event, 'source', 'unknown')
            },
            details={
                'rule_category': self.category,
                'event_data': event.data if hasattr(event, 'data') else {},
                'matched_conditions': list(self.conditions.keys())
            },
            evidence=[{
                'timestamp': event.timestamp if hasattr(event, 'timestamp') else timestamp,
                'raw_event': str(event)
            }]
        )


class RuleEngine:
    """Rule-based detection engine"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.rules = []
        
        self._load_rules()
    
    def _load_rules(self):
        """Load detection rules from configuration"""
        rules_config = self.config.get('rules', [])
        
        # Default rules if none configured
        if not rules_config:
            rules_config = self._get_default_rules()
        
        for rule_data in rules_config:
            try:
                rule = Rule(rule_data)
                self.rules.append(rule)
                self.logger.debug(f"Loaded rule: {rule.rule_id}")
            except Exception as e:
                self.logger.error(f"Error loading rule {rule_data.get('rule_id', 'unknown')}: {e}")
        
        self.logger.info(f"Loaded {len(self.rules)} detection rules")
    
    def evaluate_event(self, event) -> List[Alert]:
        """Evaluate event against all rules"""
        alerts = []
        
        for rule in self.rules:
            try:
                alert = rule.evaluate(event)
                if alert:
                    alerts.append(alert)
            except Exception as e:
                self.logger.error(f"Error evaluating rule {rule.rule_id}: {e}")
        
        return alerts
    
    def _get_default_rules(self) -> List[Dict[str, Any]]:
        """Get default detection rules"""
        return [
            {
                'rule_id': 'ssh_brute_force',
                'name': 'SSH Brute Force Attack',
                'category': 'authentication',
                'severity': 'high',
                'enabled': True,
                'conditions': {
                    'failed_ssh': {
                        'type': 'frequency',
                        'key_field': 'source_ip',
                        'threshold': 5,
                        'time_window': 300
                    },
                    'ssh_pattern': {
                        'type': 'pattern_match',
                        'field': 'message',
                        'pattern': r'Failed password.*ssh'
                    }
                }
            },
            {
                'rule_id': 'port_scan_detection',
                'name': 'Port Scanning Activity',
                'category': 'network',
                'severity': 'medium',
                'enabled': True,
                'conditions': {
                    'connection_rate': {
                        'type': 'frequency',
                        'key_field': 'source_ip',
                        'threshold': 20,
                        'time_window': 60
                    }
                }
            },
            {
                'rule_id': 'suspicious_outbound',
                'name': 'Suspicious Outbound Connection',
                'category': 'network',
                'severity': 'medium',
                'enabled': True,
                'conditions': {
                    'large_transfer': {
                        'type': 'threshold',
                        'field': 'bytes_sent',
                        'threshold': 1073741824  # 1GB
                    }
                }
            }
        ]