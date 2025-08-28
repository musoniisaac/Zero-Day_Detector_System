#!/usr/bin/env python3
"""
PCAP Analyzer Module
Offline analysis of PCAP files for anomaly detection
Created by Isaac Musoni
"""

import time
import logging
from typing import Dict, List, Callable, Any, Optional
from pathlib import Path
from collections import defaultdict, deque
from dataclasses import dataclass

try:
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logging.getLogger(__name__).warning("Scapy not available, PCAP analysis disabled")

from core.detector import SecurityEvent


@dataclass
class PcapAnalysisResult:
    """Results from PCAP analysis"""
    file_path: str
    total_packets: int
    analysis_duration: float
    events_generated: int
    flows_detected: int
    anomalies_found: int
    start_time: float
    end_time: float


class PcapAnalyzer:
    """Offline PCAP file analysis component"""
    
    def __init__(self, config: Dict[str, Any], event_callback: Callable):
        self.config = config
        self.event_callback = event_callback
        self.logger = logging.getLogger(__name__)
        
        # Analysis state
        self.flows = {}
        self.packet_count = 0
        self.events_generated = 0
        
        # Configuration
        self.protocols = config.get('protocols', ['tcp', 'udp', 'icmp'])
        self.analysis_window = config.get('analysis_window', 300)  # 5 minutes
        
        # Statistics
        self.stats = {
            'packets_processed': 0,
            'flows_tracked': 0,
            'events_generated': 0,
            'files_analyzed': 0
        }
        
        if not SCAPY_AVAILABLE:
            self.logger.error("Scapy is required for PCAP analysis")
    
    def analyze_pcap_file(self, pcap_path: str, time_acceleration: float = 1.0) -> PcapAnalysisResult:
        """
        Analyze a single PCAP file
        
        Args:
            pcap_path: Path to the PCAP file
            time_acceleration: Speed up analysis (1.0 = real-time, 10.0 = 10x faster)
        """
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy is required for PCAP analysis")
        
        pcap_file = Path(pcap_path)
        if not pcap_file.exists():
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")
        
        self.logger.info(f"Starting PCAP analysis: {pcap_path}")
        analysis_start = time.time()
        
        # Reset counters
        self.packet_count = 0
        self.events_generated = 0
        self.flows = {}
        
        try:
            # Read PCAP file
            packets = rdpcap(str(pcap_file))
            total_packets = len(packets)
            
            self.logger.info(f"Loaded {total_packets} packets from {pcap_file.name}")
            
            # Get time range from PCAP
            if packets:
                start_time = float(packets[0].time)
                end_time = float(packets[-1].time)
                pcap_duration = end_time - start_time
            else:
                start_time = end_time = time.time()
                pcap_duration = 0
            
            # Process packets
            last_packet_time = start_time
            
            for i, packet in enumerate(packets):
                packet_time = float(packet.time)
                
                # Simulate timing if requested (for real-time-like analysis)
                if time_acceleration < float('inf'):
                    time_diff = packet_time - last_packet_time
                    if time_diff > 0:
                        time.sleep(time_diff / time_acceleration)
                
                self._process_packet(packet, packet_time)
                self.packet_count += 1
                last_packet_time = packet_time
                
                # Progress logging
                if i % 10000 == 0 and i > 0:
                    progress = (i / total_packets) * 100
                    self.logger.info(f"Progress: {progress:.1f}% ({i}/{total_packets} packets)")
            
            analysis_duration = time.time() - analysis_start
            
            # Create result
            result = PcapAnalysisResult(
                file_path=str(pcap_file),
                total_packets=total_packets,
                analysis_duration=analysis_duration,
                events_generated=self.events_generated,
                flows_detected=len(self.flows),
                anomalies_found=self._count_anomalies(),
                start_time=start_time,
                end_time=end_time
            )
            
            self.stats['files_analyzed'] += 1
            self.stats['packets_processed'] += total_packets
            
            self.logger.info(f"PCAP analysis completed: {result}")
            return result
            
        except Exception as e:
            self.logger.error(f"Error analyzing PCAP file {pcap_path}: {e}")
            raise
    
    def analyze_pcap_directory(self, directory_path: str, pattern: str = "*.pcap") -> List[PcapAnalysisResult]:
        """
        Analyze all PCAP files in a directory
        
        Args:
            directory_path: Path to directory containing PCAP files
            pattern: File pattern to match (e.g., "*.pcap", "*.pcapng")
        """
        directory = Path(directory_path)
        if not directory.exists() or not directory.is_dir():
            raise ValueError(f"Directory not found: {directory_path}")
        
        pcap_files = list(directory.glob(pattern))
        if not pcap_files:
            self.logger.warning(f"No PCAP files found in {directory_path} matching {pattern}")
            return []
        
        self.logger.info(f"Found {len(pcap_files)} PCAP files to analyze")
        
        results = []
        for pcap_file in sorted(pcap_files):
            try:
                result = self.analyze_pcap_file(str(pcap_file))
                results.append(result)
            except Exception as e:
                self.logger.error(f"Failed to analyze {pcap_file}: {e}")
        
        return results
    
    def _process_packet(self, packet, packet_time: float):
        """Process individual packet from PCAP"""
        if not packet.haslayer(IP):
            return
        
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        
        # Process based on protocol
        if packet.haslayer(TCP) and 'tcp' in self.protocols:
            tcp_layer = packet[TCP]
            self._process_tcp_packet(
                src_ip, dst_ip, tcp_layer.sport, tcp_layer.dport,
                len(packet), tcp_layer.flags, packet_time
            )
        elif packet.haslayer(UDP) and 'udp' in self.protocols:
            udp_layer = packet[UDP]
            self._process_udp_packet(
                src_ip, dst_ip, udp_layer.sport, udp_layer.dport,
                len(packet), packet_time
            )
        elif packet.haslayer(ICMP) and 'icmp' in self.protocols:
            icmp_layer = packet[ICMP]
            self._process_icmp_packet(
                src_ip, dst_ip, icmp_layer.type, icmp_layer.code,
                len(packet), packet_time
            )
    
    def _process_tcp_packet(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                           packet_size: int, flags: int, packet_time: float):
        """Process TCP packet from PCAP"""
        flow_id = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
        
        # Parse TCP flags
        flag_names = []
        if flags & 0x01: flag_names.append('FIN')
        if flags & 0x02: flag_names.append('SYN')
        if flags & 0x04: flag_names.append('RST')
        if flags & 0x08: flag_names.append('PSH')
        if flags & 0x10: flag_names.append('ACK')
        if flags & 0x20: flag_names.append('URG')
        
        # Update or create flow
        if flow_id in self.flows:
            flow = self.flows[flow_id]
            flow['last_seen'] = packet_time
            flow['packets'] += 1
            flow['bytes'] += packet_size
            flow['flags'].extend(flag_names)
        else:
            flow = {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'protocol': 'tcp',
                'start_time': packet_time,
                'last_seen': packet_time,
                'bytes': packet_size,
                'packets': 1,
                'flags': flag_names
            }
            self.flows[flow_id] = flow
        
        # Check for suspicious patterns
        self._analyze_tcp_flow(flow, packet_time)
    
    def _process_udp_packet(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                           packet_size: int, packet_time: float):
        """Process UDP packet from PCAP"""
        flow_id = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
        
        # Update or create flow
        if flow_id in self.flows:
            flow = self.flows[flow_id]
            flow['last_seen'] = packet_time
            flow['packets'] += 1
            flow['bytes'] += packet_size
        else:
            flow = {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'protocol': 'udp',
                'start_time': packet_time,
                'last_seen': packet_time,
                'bytes': packet_size,
                'packets': 1,
                'flags': []
            }
            self.flows[flow_id] = flow
        
        # Check for suspicious patterns
        self._analyze_udp_flow(flow, packet_time)
    
    def _process_icmp_packet(self, src_ip: str, dst_ip: str, icmp_type: int, icmp_code: int,
                            packet_size: int, packet_time: float):
        """Process ICMP packet from PCAP"""
        event = SecurityEvent(
            timestamp=packet_time,
            source_ip=src_ip,
            event_type='icmp_traffic',
            data={
                'dst_ip': dst_ip,
                'icmp_type': icmp_type,
                'icmp_code': icmp_code,
                'packet_size': packet_size,
                'source': 'pcap_analysis'
            },
            source="pcap_analyzer"
        )
        
        self.event_callback(event)
        self.events_generated += 1
    
    def _analyze_tcp_flow(self, flow: Dict[str, Any], packet_time: float):
        """Analyze TCP flow for suspicious patterns"""
        # Check for port scanning (SYN without ACK)
        if 'SYN' in flow['flags'] and 'ACK' not in flow['flags']:
            self._check_port_scan_pcap(flow['src_ip'], packet_time)
        
        # Check for large data transfers
        if flow['bytes'] > 1073741824:  # 1GB
            self._generate_pcap_alert(
                'large_data_transfer',
                flow['src_ip'],
                {
                    'dst_ip': flow['dst_ip'],
                    'dst_port': flow['dst_port'],
                    'bytes_sent': flow['bytes'],
                    'duration': packet_time - flow['start_time'],
                    'source': 'pcap_analysis'
                },
                'medium',
                packet_time
            )
    
    def _analyze_udp_flow(self, flow: Dict[str, Any], packet_time: float):
        """Analyze UDP flow for suspicious patterns"""
        # Check for UDP flood
        duration = packet_time - flow['start_time']
        if flow['packets'] > 1000 and duration < 60:
            self._generate_pcap_alert(
                'udp_flood',
                flow['src_ip'],
                {
                    'dst_ip': flow['dst_ip'],
                    'dst_port': flow['dst_port'],
                    'packets_sent': flow['packets'],
                    'duration': duration,
                    'source': 'pcap_analysis'
                },
                'high',
                packet_time
            )
    
    def _check_port_scan_pcap(self, src_ip: str, packet_time: float):
        """Check for port scanning in PCAP data"""
        window_start = packet_time - 60  # 1 minute window
        
        # Count unique ports accessed by this IP
        unique_ports = set()
        connection_count = 0
        
        for flow in self.flows.values():
            if (flow['src_ip'] == src_ip and 
                flow['start_time'] >= window_start and
                flow['protocol'] == 'tcp'):
                unique_ports.add(flow['dst_port'])
                connection_count += 1
        
        # Trigger alert if thresholds exceeded
        if len(unique_ports) >= 10 and connection_count >= 20:
            self._generate_pcap_alert(
                'port_scan_detected',
                src_ip,
                {
                    'unique_ports': len(unique_ports),
                    'connection_count': connection_count,
                    'time_window': 60,
                    'source': 'pcap_analysis'
                },
                'medium',
                packet_time
            )
    
    def _generate_pcap_alert(self, alert_type: str, src_ip: str, details: Dict[str, Any], 
                            severity: str, packet_time: float):
        """Generate alert from PCAP analysis"""
        event = SecurityEvent(
            timestamp=packet_time,
            source_ip=src_ip,
            event_type=alert_type,
            data=details,
            severity=severity,
            source="pcap_analyzer"
        )
        
        self.event_callback(event)
        self.events_generated += 1
    
    def _count_anomalies(self) -> int:
        """Count detected anomalies"""
        return self.events_generated
    
    def get_analysis_summary(self) -> Dict[str, Any]:
        """Get summary of PCAP analysis"""
        return {
            'total_flows': len(self.flows),
            'packets_processed': self.packet_count,
            'events_generated': self.events_generated,
            'top_talkers': self._get_top_talkers(),
            'protocol_distribution': self._get_protocol_distribution(),
            'port_distribution': self._get_port_distribution()
        }
    
    def _get_top_talkers(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top traffic sources by volume"""
        ip_stats = defaultdict(lambda: {'bytes': 0, 'packets': 0, 'flows': 0})
        
        for flow in self.flows.values():
            src_ip = flow['src_ip']
            ip_stats[src_ip]['bytes'] += flow['bytes']
            ip_stats[src_ip]['packets'] += flow['packets']
            ip_stats[src_ip]['flows'] += 1
        
        # Sort by bytes and return top talkers
        sorted_ips = sorted(ip_stats.items(), key=lambda x: x[1]['bytes'], reverse=True)
        
        return [
            {
                'ip': ip,
                'bytes': stats['bytes'],
                'packets': stats['packets'],
                'flows': stats['flows']
            }
            for ip, stats in sorted_ips[:limit]
        ]
    
    def _get_protocol_distribution(self) -> Dict[str, int]:
        """Get distribution of protocols"""
        protocols = defaultdict(int)
        for flow in self.flows.values():
            protocols[flow['protocol']] += 1
        return dict(protocols)
    
    def _get_port_distribution(self) -> Dict[int, int]:
        """Get distribution of destination ports"""
        ports = defaultdict(int)
        for flow in self.flows.values():
            if 'dst_port' in flow:
                ports[flow['dst_port']] += 1
        
        # Return top 20 ports
        sorted_ports = sorted(ports.items(), key=lambda x: x[1], reverse=True)
        return dict(sorted_ports[:20])
    
    def export_results(self, output_file: str, results: List[PcapAnalysisResult]):
        """Export analysis results to file"""
        import json
        
        output_data = {
            'analysis_timestamp': time.time(),
            'total_files_analyzed': len(results),
            'results': [
                {
                    'file_path': result.file_path,
                    'total_packets': result.total_packets,
                    'analysis_duration': result.analysis_duration,
                    'events_generated': result.events_generated,
                    'flows_detected': result.flows_detected,
                    'anomalies_found': result.anomalies_found,
                    'pcap_start_time': result.start_time,
                    'pcap_end_time': result.end_time
                }
                for result in results
            ],
            'summary': self.get_analysis_summary()
        }
        
        with open(output_file, 'w') as f:
            json.dump(output_data, f, indent=2)
        
        self.logger.info(f"Analysis results exported to {output_file}")