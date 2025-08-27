#!/usr/bin/env python3
"""
Core Detection Engine
Main orchestrator for the Zero-Day Detector system
"""

import time
import threading
import queue
import logging
from typing import Dict, List, Any, Optional
from collections import defaultdict
from dataclasses import dataclass

from .rule_engine import RuleEngine
from .statistical_analyzer import StatisticalAnalyzer
from .alert_manager import AlertManager
from monitors.log_monitor import LogMonitor
from monitors.network_monitor import NetworkMonitor


@dataclass
class SecurityEvent:
    """Security event data structure"""
    timestamp: float
    source_ip: str
    event_type: str
    data: Dict[str, Any]
    severity: str = "info"
    source: str = "unknown"


class ZeroDayDetector:
    """Main detection engine orchestrator"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Initialize components
        self.rule_engine = RuleEngine(config.get('rules', {}))
        self.statistical_analyzer = StatisticalAnalyzer(config.get('statistics', {}))
        self.alert_manager = AlertManager(config.get('alerts', {}))
        
        # Event processing
        self.event_queue = queue.Queue(maxsize=config.get('system', {}).get('queue_size', 10000))
        self.running = False
        self.workers = []
        
        # Monitors
        self.monitors = []
        self._initialize_monitors()
        
        # Performance tracking
        self.stats = {
            'events_processed': 0,
            'alerts_generated': 0,
            'start_time': 0
        }
    
    def _initialize_monitors(self):
        """Initialize data collection monitors"""
        # Log monitor
        if self.config.get('data_sources', {}).get('system_logs', {}).get('enabled', True):
            log_monitor = LogMonitor(
                self.config['data_sources']['system_logs'],
                self._process_event
            )
            self.monitors.append(log_monitor)
        
        # Network monitor
        if self.config.get('data_sources', {}).get('network', {}).get('enabled', True):
            network_monitor = NetworkMonitor(
                self.config['data_sources']['network'],
                self._process_event
            )
            self.monitors.append(network_monitor)
    
    def start(self):
        """Start the detection system"""
        if self.running:
            self.logger.warning("Detector is already running")
            return
        
        self.running = True
        self.stats['start_time'] = time.time()
        
        # Start worker threads
        worker_count = self.config.get('system', {}).get('worker_threads', 4)
        for i in range(worker_count):
            worker = threading.Thread(
                target=self._worker_loop,
                name=f"DetectionWorker-{i}",
                daemon=True
            )
            worker.start()
            self.workers.append(worker)
        
        # Start monitors
        for monitor in self.monitors:
            monitor.start()
        
        # Start performance monitoring
        perf_thread = threading.Thread(
            target=self._performance_monitor,
            name="PerformanceMonitor",
            daemon=True
        )
        perf_thread.start()
        
        self.logger.info(f"Zero-Day Detector started with {len(self.workers)} workers")
        self.logger.info(f"Active monitors: {len(self.monitors)}")
    
    def stop(self):
        """Stop the detection system gracefully"""
        if not self.running:
            return
        
        self.logger.info("Stopping Zero-Day Detector...")
        self.running = False
        
        # Stop monitors
        for monitor in self.monitors:
            monitor.stop()
        
        # Wait for queue to empty
        self.logger.info("Waiting for event queue to empty...")
        self.event_queue.join()
        
        # Wait for workers to finish
        for worker in self.workers:
            worker.join(timeout=5.0)
        
        self.logger.info("Zero-Day Detector stopped")
    
    def is_running(self) -> bool:
        """Check if detector is running"""
        return self.running
    
    def _process_event(self, event: SecurityEvent):
        """Add event to processing queue"""
        try:
            self.event_queue.put_nowait(event)
        except queue.Full:
            self.logger.warning("Event queue full, dropping event")
    
    def _worker_loop(self):
        """Main detection processing loop"""
        while self.running:
            try:
                # Get event from queue with timeout
                event = self.event_queue.get(timeout=1.0)
                
                # Process through rule engine
                rule_alerts = self.rule_engine.evaluate_event(event)
                
                # Process through statistical analyzer
                stat_alerts = self.statistical_analyzer.evaluate_event(event)
                
                # Combine alerts
                all_alerts = rule_alerts + stat_alerts
                
                # Send alerts through alert manager
                for alert in all_alerts:
                    self.alert_manager.process_alert(alert)
                    self.stats['alerts_generated'] += 1
                
                self.stats['events_processed'] += 1
                self.event_queue.task_done()
                
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Error in worker loop: {e}")
    
    def _performance_monitor(self):
        """Monitor system performance"""
        import psutil
        
        process = psutil.Process()
        
        while self.running:
            try:
                # Get current resource usage
                cpu_percent = process.cpu_percent()
                memory_mb = process.memory_info().rss / 1024 / 1024
                
                # Check thresholds
                max_cpu = self.config.get('system', {}).get('max_cpu_usage', 5.0)
                max_memory = self.config.get('system', {}).get('max_memory_mb', 512)
                
                if cpu_percent > max_cpu:
                    self.logger.warning(f"CPU usage high: {cpu_percent:.1f}%")
                
                if memory_mb > max_memory:
                    self.logger.warning(f"Memory usage high: {memory_mb:.1f}MB")
                
                # Log performance stats every 5 minutes
                if int(time.time()) % 300 == 0:
                    uptime = time.time() - self.stats['start_time']
                    eps = self.stats['events_processed'] / max(uptime, 1)
                    
                    self.logger.info(
                        f"Performance: CPU={cpu_percent:.1f}%, "
                        f"Memory={memory_mb:.1f}MB, "
                        f"Events/sec={eps:.1f}, "
                        f"Queue={self.event_queue.qsize()}"
                    )
                
                time.sleep(10)  # Check every 10 seconds
                
            except Exception as e:
                self.logger.error(f"Performance monitoring error: {e}")
                time.sleep(30)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current system statistics"""
        uptime = time.time() - self.stats['start_time'] if self.stats['start_time'] else 0
        
        return {
            'uptime_seconds': uptime,
            'events_processed': self.stats['events_processed'],
            'alerts_generated': self.stats['alerts_generated'],
            'events_per_second': self.stats['events_processed'] / max(uptime, 1),
            'queue_size': self.event_queue.qsize(),
            'active_workers': len([w for w in self.workers if w.is_alive()]),
            'active_monitors': len(self.monitors)
        }