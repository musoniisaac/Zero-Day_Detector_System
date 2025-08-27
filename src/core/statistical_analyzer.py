#!/usr/bin/env python3
"""
Statistical Analyzer
Real-time anomaly detection using statistical methods
Created by Isaac Musoni
"""

import time
import logging
import numpy as np
from typing import Dict, List, Any, Optional
from collections import defaultdict, deque
from dataclasses import dataclass

from .rule_engine import Alert


@dataclass
class MetricBaseline:
    """Statistical baseline for a metric"""
    name: str
    values: deque
    mean: float
    std_dev: float
    percentile_95: float
    last_updated: float


class StatisticalAnalyzer:
    """Real-time statistical anomaly detection"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Configuration
        self.baseline_window_hours = config.get('baseline_window_hours', 168)  # 7 days
        self.anomaly_sensitivity = config.get('anomaly_sensitivity', 'medium')
        self.min_baseline_samples = config.get('min_baseline_samples', 100)
        
        # Data storage
        self.baselines = {}
        self.metric_windows = defaultdict(lambda: deque(maxlen=self.baseline_window_hours * 60))  # minutes
        
        # Sensitivity thresholds for Z-score
        self.thresholds = {
            'low': 3.0,      # 99.7% confidence
            'medium': 2.5,   # 98.8% confidence
            'high': 2.0,     # 95.4% confidence
            'very_high': 1.5 # 86.6% confidence
        }
        
        self.logger.info(f"Statistical analyzer initialized with {self.anomaly_sensitivity} sensitivity")
    
    def evaluate_event(self, event) -> List[Alert]:
        """Evaluate event for statistical anomalies"""
        alerts = []
        current_time = time.time()
        
        # Extract metrics from event
        metrics = self._extract_metrics(event)
        
        for metric_name, value in metrics.items():
            # Update baseline data
            self._update_baseline(metric_name, value, current_time)
            
            # Check for anomalies
            anomaly_result = self._detect_anomaly(metric_name, value, current_time)
            
            if anomaly_result['is_anomaly']:
                alert = self._create_statistical_alert(
                    metric_name, 
                    value, 
                    anomaly_result,
                    event,
                    current_time
                )
                alerts.append(alert)
        
        return alerts
    
    def _extract_metrics(self, event) -> Dict[str, float]:
        """Extract numerical metrics from security event"""
        metrics = {}
        
        if not hasattr(event, 'data') or not event.data:
            return metrics
        
        data = event.data
        
        # Network-related metrics
        if 'connection_count' in data:
            metrics['connections_per_minute'] = float(data['connection_count'])
        
        if 'bytes_sent' in data:
            metrics['bytes_per_second'] = float(data['bytes_sent'])
        
        if 'unique_ports' in data:
            metrics['ports_accessed_per_minute'] = float(data['unique_ports'])
        
        if 'failed_logins' in data:
            metrics['failed_auth_per_hour'] = float(data['failed_logins'])
        
        if 'packet_count' in data:
            metrics['packets_per_second'] = float(data['packet_count'])
        
        if 'request_rate' in data:
            metrics['requests_per_minute'] = float(data['request_rate'])
        
        # System metrics
        if 'cpu_usage' in data:
            metrics['cpu_usage_percent'] = float(data['cpu_usage'])
        
        if 'memory_usage' in data:
            metrics['memory_usage_mb'] = float(data['memory_usage'])
        
        return metrics
    
    def _update_baseline(self, metric_name: str, value: float, timestamp: float):
        """Update statistical baseline for metric"""
        # Add value to time-series window
        self.metric_windows[metric_name].append((timestamp, value))
        
        # Update baseline statistics if we have enough data
        if len(self.metric_windows[metric_name]) >= self.min_baseline_samples:
            values = [v for t, v in self.metric_windows[metric_name]]
            
            # Calculate statistics
            mean = np.mean(values)
            std_dev = np.std(values)
            percentile_95 = np.percentile(values, 95)
            
            baseline = MetricBaseline(
                name=metric_name,
                values=deque(values[-168:], maxlen=168),  # Keep last week
                mean=mean,
                std_dev=std_dev,
                percentile_95=percentile_95,
                last_updated=timestamp
            )
            
            self.baselines[metric_name] = baseline
    
    def _detect_anomaly(self, metric_name: str, current_value: float, timestamp: float) -> Dict[str, Any]:
        """Detect if current value is anomalous"""
        if metric_name not in self.baselines:
            return {'is_anomaly': False, 'reason': 'insufficient_data'}
        
        baseline = self.baselines[metric_name]
        
        # Calculate Z-score
        if baseline.std_dev == 0:
            z_score = 0
        else:
            z_score = abs(current_value - baseline.mean) / baseline.std_dev
        
        # Check against threshold
        threshold = self.thresholds.get(self.anomaly_sensitivity, 2.5)
        z_score_anomaly = z_score > threshold
        
        # Additional checks
        percentile_anomaly = current_value > (baseline.percentile_95 * 1.5)
        
        # Trend analysis
        trend_anomaly = self._detect_trend_anomaly(metric_name, current_value, timestamp)
        
        is_anomaly = z_score_anomaly or percentile_anomaly or trend_anomaly
        
        return {
            'is_anomaly': is_anomaly,
            'z_score': z_score,
            'threshold': threshold,
            'baseline_mean': baseline.mean,
            'baseline_std': baseline.std_dev,
            'percentile_95': baseline.percentile_95,
            'confidence': min(1.0, z_score / threshold) if threshold > 0 else 0,
            'anomaly_types': {
                'z_score': z_score_anomaly,
                'percentile': percentile_anomaly,
                'trend': trend_anomaly
            }
        }
    
    def _detect_trend_anomaly(self, metric_name: str, current_value: float, timestamp: float) -> bool:
        """Detect trend-based anomalies"""
        if metric_name not in self.metric_windows:
            return False
        
        data = list(self.metric_windows[metric_name])
        
        if len(data) < 24:  # Need at least 24 data points
            return False
        
        # Compare recent average to historical average
        recent_values = [v for t, v in data[-12:]]  # Last 12 points
        historical_values = [v for t, v in data[:-12]]  # Everything else
        
        if not historical_values:
            return False
        
        recent_avg = np.mean(recent_values)
        historical_avg = np.mean(historical_values)
        
        if historical_avg == 0:
            return recent_avg > 0
        
        # Check for significant change
        change_ratio = recent_avg / historical_avg
        return change_ratio > 3.0 or change_ratio < 0.3
    
    def _create_statistical_alert(self, metric_name: str, value: float, 
                                anomaly_result: Dict, event, timestamp: float) -> Alert:
        """Create alert for statistical anomaly"""
        
        # Determine severity based on confidence
        confidence = anomaly_result['confidence']
        if confidence > 0.9:
            severity = 'critical'
        elif confidence > 0.7:
            severity = 'high'
        elif confidence > 0.5:
            severity = 'medium'
        else:
            severity = 'low'
        
        alert_id = f"stat_alert_{int(timestamp)}_{metric_name}_{hash(str(value)) % 10000:04d}"
        
        return Alert(
            alert_id=alert_id,
            timestamp=timestamp,
            rule_id=f"statistical_{metric_name}",
            rule_name=f"Statistical Anomaly: {metric_name}",
            severity=severity,
            source={
                'ip_address': getattr(event, 'source_ip', 'unknown'),
                'event_type': 'statistical_anomaly',
                'source': getattr(event, 'source', 'statistical_analyzer')
            },
            details={
                'metric_name': metric_name,
                'current_value': value,
                'z_score': anomaly_result['z_score'],
                'confidence': confidence,
                'baseline_mean': anomaly_result['baseline_mean'],
                'baseline_std': anomaly_result['baseline_std'],
                'percentile_95': anomaly_result['percentile_95'],
                'anomaly_types': anomaly_result['anomaly_types']
            },
            evidence=[{
                'timestamp': timestamp,
                'metric_value': value,
                'baseline_data': {
                    'mean': anomaly_result['baseline_mean'],
                    'std_dev': anomaly_result['baseline_std']
                }
            }]
        )
    
    def get_baseline_info(self, metric_name: str) -> Optional[Dict[str, Any]]:
        """Get baseline information for a metric"""
        if metric_name not in self.baselines:
            return None
        
        baseline = self.baselines[metric_name]
        return {
            'name': baseline.name,
            'mean': baseline.mean,
            'std_dev': baseline.std_dev,
            'percentile_95': baseline.percentile_95,
            'sample_count': len(baseline.values),
            'last_updated': baseline.last_updated
        }
    
    def get_all_baselines(self) -> Dict[str, Dict[str, Any]]:
        """Get all baseline information"""
        return {name: self.get_baseline_info(name) for name in self.baselines.keys()}