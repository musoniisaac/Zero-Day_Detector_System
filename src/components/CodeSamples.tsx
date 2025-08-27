import React, { useState } from 'react';
import { Code, FileText, Network, Activity } from 'lucide-react';

export function CodeSamples() {
  const [codeSection, setCodeSection] = useState<'core' | 'parser' | 'network' | 'stats'>('core');

  const codeSamples = {
    core: {
      title: 'Core Detection Engine',
      description: 'Main detection loop and event processing logic',
      code: `#!/usr/bin/env python3
"""
Zero-Day Detector - Core Detection Engine
Lightweight real-time security monitoring system
"""

import time
import json
import threading
import queue
from typing import Dict, List, Any
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta

@dataclass
class SecurityEvent:
    timestamp: float
    source_ip: str
    event_type: str
    data: Dict[str, Any]
    severity: str = "info"

@dataclass  
class Alert:
    alert_id: str
    timestamp: float
    rule_id: str
    severity: str
    source: Dict[str, Any]
    details: Dict[str, Any]
    evidence: List[Dict[str, Any]]

class ZeroDayDetector:
    def __init__(self, config_path: str):
        self.config = self.load_config(config_path)
        self.rule_engine = RuleEngine(self.config['rules'])
        self.statistical_analyzer = StatisticalAnalyzer(self.config['statistics'])
        self.alert_manager = AlertManager(self.config['alerts'])
        
        self.event_queue = queue.Queue(maxsize=10000)
        self.running = False
        self.workers = []
    
    def start(self):
        """Start the detection system"""
        self.running = True
        
        # Start worker threads
        for i in range(self.config['system']['worker_threads']):
            worker = threading.Thread(target=self._worker_loop, daemon=True)
            worker.start()
            self.workers.append(worker)
        
        # Start data collectors
        self._start_collectors()
        
        print(f"Zero-Day Detector started with {len(self.workers)} workers")
    
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
                
                # Combine and deduplicate alerts
                all_alerts = self._merge_alerts(rule_alerts, stat_alerts)
                
                # Send alerts through alert manager
                for alert in all_alerts:
                    self.alert_manager.process_alert(alert)
                    
                self.event_queue.task_done()
                
            except queue.Empty:
                continue
            except Exception as e:
                print(f"Error in worker loop: {e}")
    
    def process_event(self, event: SecurityEvent):
        """Add event to processing queue"""
        try:
            self.event_queue.put_nowait(event)
        except queue.Full:
            print("Event queue full, dropping event")
    
    def _start_collectors(self):
        """Initialize data collection threads"""
        # Log file monitoring
        log_collector = LogCollector(self.config['data_sources']['system_logs'])
        log_thread = threading.Thread(target=log_collector.start, args=(self.process_event,), daemon=True)
        log_thread.start()
        
        # Network packet monitoring  
        net_collector = NetworkCollector(self.config['data_sources']['network'])
        net_thread = threading.Thread(target=net_collector.start, args=(self.process_event,), daemon=True)
        net_thread.start()
    
    def stop(self):
        """Gracefully stop the detection system"""
        self.running = False
        
        # Wait for queue to empty
        self.event_queue.join()
        
        # Wait for workers to finish
        for worker in self.workers:
            worker.join(timeout=5.0)
        
        print("Zero-Day Detector stopped")

if __name__ == "__main__":
    detector = ZeroDayDetector("/etc/zdd/config.yaml")
    
    try:
        detector.start()
        
        # Keep main thread alive
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("Shutting down...")
        detector.stop()`
    },
    parser: {
      title: 'Log Parser Module',
      description: 'Multi-format log parsing with normalized output',
      code: `#!/usr/bin/env python3
"""
Log Parser Module
Supports multiple log formats with standardized output
"""

import re
import json
from typing import Dict, Any, Optional
from datetime import datetime
from enum import Enum

class LogFormat(Enum):
    SYSLOG = "syslog"
    APACHE = "apache"
    IIS = "iis" 
    CEF = "cef"
    JSON = "json"

class LogParser:
    def __init__(self):
        self.parsers = {
            LogFormat.SYSLOG: self._parse_syslog,
            LogFormat.APACHE: self._parse_apache,
            LogFormat.IIS: self._parse_iis,
            LogFormat.CEF: self._parse_cef,
            LogFormat.JSON: self._parse_json
        }
        
        # Compiled regex patterns for performance
        self.patterns = self._compile_patterns()
    
    def parse_log_line(self, line: str, format_type: LogFormat) -> Optional[Dict[str, Any]]:
        """Parse a single log line based on format type"""
        if format_type not in self.parsers:
            raise ValueError(f"Unsupported log format: {format_type}")
        
        try:
            return self.parsers[format_type](line.strip())
        except Exception as e:
            print(f"Error parsing log line: {e}")
            return None
    
    def _parse_syslog(self, line: str) -> Dict[str, Any]:
        """Parse syslog format: <priority>timestamp hostname program: message"""
        pattern = self.patterns['syslog']
        match = pattern.match(line)
        
        if not match:
            return None
        
        groups = match.groupdict()
        
        return {
            'timestamp': self._parse_timestamp(groups.get('timestamp')),
            'hostname': groups.get('hostname', ''),
            'program': groups.get('program', ''),
            'message': groups.get('message', ''),
            'facility': int(groups.get('priority', 0)) >> 3,
            'severity': int(groups.get('priority', 0)) & 7,
            'raw_line': line
        }
    
    def _parse_apache(self, line: str) -> Dict[str, Any]:
        """Parse Apache Common Log Format"""
        pattern = self.patterns['apache']
        match = pattern.match(line)
        
        if not match:
            return None
        
        groups = match.groupdict()
        
        return {
            'timestamp': self._parse_timestamp(groups.get('timestamp')),
            'client_ip': groups.get('client_ip', ''),
            'method': groups.get('method', ''),
            'url': groups.get('url', ''),
            'protocol': groups.get('protocol', ''),
            'status_code': int(groups.get('status', 0)),
            'bytes_sent': int(groups.get('bytes', 0)),
            'user_agent': groups.get('user_agent', ''),
            'referer': groups.get('referer', ''),
            'raw_line': line
        }
    
    def _parse_iis(self, line: str) -> Dict[str, Any]:
        """Parse IIS W3C Extended Log Format"""
        if line.startswith('#'):
            return None  # Skip header lines
        
        fields = line.split(' ')
        
        if len(fields) < 10:
            return None
        
        return {
            'timestamp': self._parse_timestamp(f"{fields[0]} {fields[1]}"),
            'server_ip': fields[2],
            'method': fields[3], 
            'uri_stem': fields[4],
            'uri_query': fields[5],
            'server_port': int(fields[6]) if fields[6] != '-' else 0,
            'username': fields[7] if fields[7] != '-' else '',
            'client_ip': fields[8],
            'user_agent': fields[9] if len(fields) > 9 else '',
            'raw_line': line
        }
    
    def _compile_patterns(self) -> Dict[str, re.Pattern]:
        """Compile regex patterns for log formats"""
        return {
            'syslog': re.compile(
                r'^<(?P<priority>\d+)>(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+'
                r'(?P<hostname>\S+)\s+(?P<program>\S+?):\s*(?P<message>.*)$'
            ),
            'apache': re.compile(
                r'^(?P<client_ip>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+'
                r'"(?P<method>\S+)\s+(?P<url>\S+)\s+(?P<protocol>[^"]+)"\s+'
                r'(?P<status>\d+)\s+(?P<bytes>\S+)(?:\s+"(?P<referer>[^"]*)")?\s*'
                r'(?:"(?P<user_agent>[^"]*)")?'
            )
        }
    
    def _parse_timestamp(self, timestamp_str: str) -> float:
        """Convert timestamp string to Unix timestamp"""
        if not timestamp_str:
            return time.time()
        
        # Handle different timestamp formats
        formats = [
            "%b %d %H:%M:%S",           # Syslog format
            "%d/%b/%Y:%H:%M:%S %z",     # Apache format
            "%Y-%m-%d %H:%M:%S",        # IIS format
            "%Y-%m-%dT%H:%M:%S.%fZ"     # ISO format
        ]
        
        for fmt in formats:
            try:
                dt = datetime.strptime(timestamp_str.split()[0], fmt)
                return dt.timestamp()
            except ValueError:
                continue
        
        # If no format matches, return current time
        return time.time()`
    },
    network: {
      title: 'Network Monitor',
      description: 'Real-time network traffic analysis and flow tracking',
      code: `#!/usr/bin/env python3
"""
Network Monitor Module
Real-time network traffic analysis for Zero-Day detection
"""

import socket
import struct
import threading
import time
from typing import Dict, List, Callable, Any
from collections import defaultdict, deque
from dataclasses import dataclass

@dataclass
class NetworkFlow:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_time: float
    last_seen: float
    bytes_sent: int
    packets_sent: int

class NetworkMonitor:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.active_flows = {}
        self.flow_stats = defaultdict(lambda: deque(maxlen=1000))
        self.running = False
        self.event_callback = None
        
    def start(self, event_callback: Callable):
        """Start network monitoring"""
        self.event_callback = event_callback
        self.running = True
        
        # Start packet capture thread for each interface
        for interface in self.config.get('interfaces', ['eth0']):
            capture_thread = threading.Thread(
                target=self._packet_capture_loop,
                args=(interface,),
                daemon=True
            )
            capture_thread.start()
        
        # Start flow analysis thread
        analysis_thread = threading.Thread(
            target=self._flow_analysis_loop,
            daemon=True
        )
        analysis_thread.start()
    
    def _packet_capture_loop(self, interface: str):
        """Capture and analyze network packets"""
        try:
            # Create raw socket for packet capture
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            sock.bind((interface, 0))
            
            while self.running:
                try:
                    packet, addr = sock.recvfrom(65536)
                    self._process_packet(packet, interface)
                except socket.error as e:
                    if self.running:  # Only log if we're still supposed to be running
                        print(f"Socket error on {interface}: {e}")
                        time.sleep(1)
                        
        except Exception as e:
            print(f"Error starting packet capture on {interface}: {e}")
    
    def _process_packet(self, packet: bytes, interface: str):
        """Process individual network packet"""
        try:
            # Parse Ethernet header (14 bytes)
            eth_header = struct.unpack('!6s6sH', packet[:14])
            eth_type = eth_header[2]
            
            # Check if IP packet (0x0800)
            if eth_type != 0x0800:
                return
            
            # Parse IP header
            ip_header = struct.unpack('!BBHHHBBH4s4s', packet[14:34])
            
            version_ihl = ip_header[0]
            ihl = (version_ihl & 0xF) * 4
            protocol = ip_header[6]
            src_ip = socket.inet_ntoa(ip_header[8])
            dst_ip = socket.inet_ntoa(ip_header[9])
            
            # Parse transport layer based on protocol
            if protocol == 6:  # TCP
                self._process_tcp_packet(packet, 14 + ihl, src_ip, dst_ip)
            elif protocol == 17:  # UDP
                self._process_udp_packet(packet, 14 + ihl, src_ip, dst_ip)
            elif protocol == 1:   # ICMP
                self._process_icmp_packet(packet, 14 + ihl, src_ip, dst_ip)
                
        except Exception as e:
            # Silently ignore malformed packets
            pass
    
    def _process_tcp_packet(self, packet: bytes, offset: int, src_ip: str, dst_ip: str):
        """Process TCP packet and update flow tracking"""
        try:
            # Parse TCP header
            tcp_header = struct.unpack('!HHLLBBHHH', packet[offset:offset+20])
            src_port = tcp_header[0]
            dst_port = tcp_header[1]
            flags = tcp_header[5]
            
            # Create flow identifier
            flow_id = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
            
            current_time = time.time()
            
            # Update or create flow
            if flow_id in self.active_flows:
                flow = self.active_flows[flow_id]
                flow.last_seen = current_time
                flow.packets_sent += 1
                flow.bytes_sent += len(packet)
            else:
                flow = NetworkFlow(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol="tcp",
                    start_time=current_time,
                    last_seen=current_time,
                    bytes_sent=len(packet),
                    packets_sent=1
                )
                self.active_flows[flow_id] = flow
            
            # Check for suspicious patterns
            self._analyze_tcp_flow(flow, flags)
            
        except Exception:
            pass
    
    def _analyze_tcp_flow(self, flow: NetworkFlow, tcp_flags: int):
        """Analyze TCP flow for suspicious patterns"""
        # Check for port scanning (SYN without ACK)
        if tcp_flags & 0x02 and not tcp_flags & 0x10:  # SYN flag set, ACK not set
            self._check_port_scan(flow.src_ip)
        
        # Check for connection rate anomalies
        self._check_connection_rate(flow.src_ip, flow.dst_port)
    
    def _check_port_scan(self, src_ip: str):
        """Check if source IP is performing port scanning"""
        current_time = time.time()
        window_start = current_time - 60  # 1 minute window
        
        # Count unique ports accessed by this IP
        unique_ports = set()
        connection_count = 0
        
        for flow in self.active_flows.values():
            if (flow.src_ip == src_ip and 
                flow.start_time >= window_start):
                unique_ports.add(flow.dst_port)
                connection_count += 1
        
        # Trigger alert if thresholds exceeded
        if len(unique_ports) >= 10 and connection_count >= 20:
            self._generate_network_alert(
                "port_scan_detected",
                src_ip,
                {
                    'unique_ports': len(unique_ports),
                    'connection_count': connection_count,
                    'time_window': 60
                }
            )
    
    def _generate_network_alert(self, alert_type: str, src_ip: str, details: Dict[str, Any]):
        """Generate network-based security alert"""
        if self.event_callback:
            event = SecurityEvent(
                timestamp=time.time(),
                source_ip=src_ip,
                event_type=alert_type,
                data=details,
                severity="medium"
            )
            self.event_callback(event)`
    },
    stats: {
      title: 'Statistical Analyzer',
      description: 'Real-time statistical analysis and anomaly detection',
      code: `#!/usr/bin/env python3
"""
Statistical Analyzer Module
Real-time anomaly detection using statistical methods
"""

import numpy as np
import time
from typing import Dict, List, Any, Optional
from collections import defaultdict, deque
from dataclasses import dataclass

@dataclass
class MetricBaseline:
    name: str
    values: deque
    mean: float
    std_dev: float
    percentile_95: float
    last_updated: float

class StatisticalAnalyzer:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.baselines = {}
        self.metric_windows = defaultdict(lambda: deque(maxlen=1440))  # 24 hours
        self.anomaly_threshold = config.get('anomaly_sensitivity', 'medium')
        
        # Sensitivity thresholds for Z-score
        self.thresholds = {
            'low': 3.0,      # 99.7% confidence
            'medium': 2.5,   # 98.8% confidence
            'high': 2.0,     # 95.4% confidence
            'very_high': 1.5 # 86.6% confidence
        }
    
    def evaluate_event(self, event) -> List[Any]:
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
                    event
                )
                alerts.append(alert)
        
        return alerts
    
    def _extract_metrics(self, event) -> Dict[str, float]:
        """Extract numerical metrics from security event"""
        metrics = {}
        
        # Network-related metrics
        if hasattr(event, 'data'):
            data = event.data
            
            if 'connection_count' in data:
                metrics['connections_per_minute'] = float(data['connection_count'])
            
            if 'bytes_sent' in data:
                metrics['bytes_per_second'] = float(data['bytes_sent'])
            
            if 'unique_ports' in data:
                metrics['ports_accessed_per_minute'] = float(data['unique_ports'])
            
            if 'failed_logins' in data:
                metrics['failed_auth_per_hour'] = float(data['failed_logins'])
        
        return metrics
    
    def _update_baseline(self, metric_name: str, value: float, timestamp: float):
        """Update statistical baseline for metric"""
        # Add value to time-series window
        self.metric_windows[metric_name].append((timestamp, value))
        
        # Update baseline statistics if we have enough data
        if len(self.metric_windows[metric_name]) >= 30:
            values = [v for t, v in self.metric_windows[metric_name]]
            
            baseline = MetricBaseline(
                name=metric_name,
                values=deque(values[-168:], maxlen=168),  # Keep last week
                mean=np.mean(values),
                std_dev=np.std(values),
                percentile_95=np.percentile(values, 95),
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
        threshold = self.thresholds.get(self.anomaly_threshold, 2.5)
        is_anomaly = z_score > threshold
        
        # Additional checks
        percentile_anomaly = current_value > (baseline.percentile_95 * 1.5)
        
        return {
            'is_anomaly': is_anomaly or percentile_anomaly,
            'z_score': z_score,
            'threshold': threshold,
            'baseline_mean': baseline.mean,
            'baseline_std': baseline.std_dev,
            'percentile_95': baseline.percentile_95,
            'confidence': 1 - (1 / (z_score + 1)) if z_score > 0 else 0
        }
    
    def _create_statistical_alert(self, metric_name: str, value: float, anomaly_result: Dict, event) -> Any:
        """Create alert for statistical anomaly"""
        return {
            'alert_type': 'statistical_anomaly',
            'metric_name': metric_name,
            'current_value': value,
            'z_score': anomaly_result['z_score'],
            'confidence': anomaly_result['confidence'],
            'baseline_mean': anomaly_result['baseline_mean'],
            'source_event': event,
            'timestamp': time.time()
        }`
    }
  };

  return (
    <div className="space-y-8">
      <div className="bg-white rounded-lg shadow-sm border border-slate-200 p-6">
        <h2 className="text-2xl font-bold text-slate-800 mb-6">Implementation Code Samples</h2>
        
        <div className="mb-6">
          <h3 className="text-xl font-semibold text-slate-700 mb-4">Core Modules</h3>
          <p className="text-slate-600 leading-relaxed mb-4">
            These code samples provide the foundation for implementing the Zero-Day Detector system. 
            Each module focuses on a specific aspect of the detection pipeline and can be extended 
            based on specific deployment requirements.
          </p>
          
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3 mb-6">
            {Object.entries(codeSamples).map(([key, sample]) => (
              <button
                key={key}
                onClick={() => setCodeSection(key as any)}
                className={`p-4 rounded-lg text-left transition-colors ${
                  codeSection === key
                    ? 'bg-blue-100 border border-blue-300 text-blue-700'
                    : 'bg-slate-50 border border-slate-200 text-slate-700 hover:bg-slate-100'
                }`}
              >
                <div className="font-medium text-sm mb-1">{sample.title}</div>
                <div className="text-xs opacity-75">{sample.description}</div>
              </button>
            ))}
          </div>

          <div className="bg-slate-900 rounded-lg p-6 text-green-400 font-mono text-sm">
            <div className="flex items-center space-x-2 mb-4">
              <Code className="h-4 w-4" />
              <span className="font-semibold">{codeSamples[codeSection].title}</span>
            </div>
            <pre className="whitespace-pre-wrap overflow-x-auto max-h-96">
              {codeSamples[codeSection].code}
            </pre>
          </div>
        </div>

        <div className="mb-8">
          <h3 className="text-xl font-semibold text-slate-700 mb-4">Build Instructions</h3>
          
          <div className="bg-slate-900 rounded-lg p-6 text-green-400 font-mono text-sm">
            <div className="flex items-center space-x-2 mb-4">
              <FileText className="h-4 w-4" />
              <span className="font-semibold">Compilation and Packaging</span>
            </div>
            <pre className="whitespace-pre-wrap overflow-x-auto">
{`# Build script for Zero-Day Detector
#!/bin/bash

# Set build parameters
VERSION="2.1.0"
BUILD_DIR="build"
DIST_DIR="dist"

# Clean previous builds
rm -rf $BUILD_DIR $DIST_DIR
mkdir -p $BUILD_DIR $DIST_DIR

# Compile Python components
python3 -m py_compile src/*.py
python3 -m compileall src/

# Create optimized bytecode
python3 -O -m py_compile src/*.py

# Package for distribution
tar -czf $DIST_DIR/zdd-linux-amd64-$VERSION.tar.gz \\
    --transform 's,^src/,bin/,' \\
    src/*.py \\
    config/ \\
    rules/ \\
    systemd/ \\
    README.md \\
    LICENSE

# Create installation package
cat > $DIST_DIR/install.sh << 'EOF'
#!/bin/bash
# Zero-Day Detector Installation Script v2.1.0

set -e

echo "Installing Zero-Day Detector v2.1.0..."

# Check for root privileges
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

# Install system dependencies
if command -v apt &> /dev/null; then
    apt update && apt install -y python3 python3-pip libpcap-dev
elif command -v yum &> /dev/null; then
    yum install -y python3 python3-pip libpcap-devel
fi

# Install Python dependencies
pip3 install numpy scipy

echo "Installation completed successfully!"
echo "Run 'systemctl start zdd-detector' to start the service"
EOF

chmod +x $DIST_DIR/install.sh

echo "Build completed: $DIST_DIR/zdd-linux-amd64-$VERSION.tar.gz"`}
            </pre>
          </div>
        </div>

        <div>
          <h3 className="text-xl font-semibold text-slate-700 mb-4">Testing Framework</h3>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <h4 className="font-semibold text-slate-700 mb-3">Unit Tests</h4>
              <div className="bg-slate-50 rounded p-4 border border-slate-200">
                <ul className="text-slate-600 space-y-1 text-sm">
                  <li>• Rule engine logic validation</li>
                  <li>• Statistical calculation accuracy</li>
                  <li>• Log parser format handling</li>
                  <li>• Alert generation and routing</li>
                  <li>• Configuration validation</li>
                </ul>
              </div>
            </div>
            
            <div>
              <h4 className="font-semibold text-slate-700 mb-3">Integration Tests</h4>
              <div className="bg-slate-50 rounded p-4 border border-slate-200">
                <ul className="text-slate-600 space-y-1 text-sm">
                  <li>• End-to-end detection scenarios</li>
                  <li>• Performance under load</li>
                  <li>• Multi-node coordination</li>
                  <li>• Alert delivery verification</li>
                  <li>• Failover and recovery</li>
                </ul>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}