#!/usr/bin/env python3
"""
Network Monitor
Real-time network traffic analysis and flow tracking
"""

import time
import socket
import struct
import threading
import logging
from typing import Dict, List, Callable, Any, Optional
from collections import defaultdict, deque
from dataclasses import dataclass

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logging.getLogger(__name__).warning("Scapy not available, using raw sockets")

from core.detector import SecurityEvent


@dataclass
class NetworkFlow:
    """Network flow data structure"""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_time: float
    last_seen: float
    bytes_sent: int
    packets_sent: int
    flags: List[str]


class NetworkMonitor:
    """Network traffic monitoring component"""
    
    def __init__(self, config: Dict[str, Any], event_callback: Callable):
        self.config = config
        self.event_callback = event_callback
        self.logger = logging.getLogger(__name__)
        
        # Flow tracking
        self.active_flows = {}
        self.flow_stats = defaultdict(lambda: deque(maxlen=1000))
        
        # Threading
        self.running = False
        self.capture_threads = []
        self.analysis_thread = None
        
        # Configuration
        self.interfaces = config.get('interfaces', ['eth0'])
        self.protocols = config.get('protocols', ['tcp', 'udp', 'icmp'])
        self.capture_filter = config.get('capture_filter', 'not broadcast and not multicast')
        
        # Statistics
        self.stats = {
            'packets_captured': 0,
            'flows_tracked': 0,
            'alerts_generated': 0
        }
    
    def start(self):
        """Start network monitoring"""
        if self.running:
            return
        
        self.running = True
        
        # Check if we have permission for packet capture
        if not self._check_capture_permissions():
            self.logger.error("Insufficient permissions for packet capture")
            return
        
        # Start packet capture for each interface
        for interface in self.interfaces:
            if self._interface_exists(interface):
                capture_thread = threading.Thread(
                    target=self._packet_capture_loop,
                    args=(interface,),
                    name=f"NetworkCapture-{interface}",
                    daemon=True
                )
                capture_thread.start()
                self.capture_threads.append(capture_thread)
            else:
                self.logger.warning(f"Network interface not found: {interface}")
        
        # Start flow analysis thread
        self.analysis_thread = threading.Thread(
            target=self._flow_analysis_loop,
            name="FlowAnalysis",
            daemon=True
        )
        self.analysis_thread.start()
        
        self.logger.info(f"Network monitor started on {len(self.capture_threads)} interfaces")
    
    def stop(self):
        """Stop network monitoring"""
        if not self.running:
            return
        
        self.running = False
        
        # Wait for threads to finish
        for thread in self.capture_threads:
            thread.join(timeout=5.0)
        
        if self.analysis_thread:
            self.analysis_thread.join(timeout=5.0)
        
        self.logger.info("Network monitor stopped")
    
    def _check_capture_permissions(self) -> bool:
        """Check if we have permissions for packet capture"""
        try:
            # Try to create a raw socket
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            sock.close()
            return True
        except PermissionError:
            return False
        except Exception:
            return False
    
    def _interface_exists(self, interface: str) -> bool:
        """Check if network interface exists"""
        try:
            with open(f'/sys/class/net/{interface}/operstate', 'r') as f:
                state = f.read().strip()
                return state in ['up', 'down', 'unknown']
        except FileNotFoundError:
            return False
    
    def _packet_capture_loop(self, interface: str):
        """Capture and analyze network packets"""
        self.logger.info(f"Starting packet capture on {interface}")
        
        try:
            if SCAPY_AVAILABLE:
                self._scapy_capture(interface)
            else:
                self._raw_socket_capture(interface)
        except Exception as e:
            self.logger.error(f"Error in packet capture on {interface}: {e}")
    
    def _scapy_capture(self, interface: str):
        """Capture packets using Scapy"""
        def packet_handler(packet):
            if not self.running:
                return
            
            try:
                self._process_packet_scapy(packet, interface)
                self.stats['packets_captured'] += 1
            except Exception as e:
                self.logger.debug(f"Error processing packet: {e}")
        
        # Start sniffing
        sniff(
            iface=interface,
            prn=packet_handler,
            filter=self.capture_filter,
            store=False,
            stop_filter=lambda x: not self.running
        )
    
    def _raw_socket_capture(self, interface: str):
        """Capture packets using raw sockets"""
        try:
            # Create raw socket
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            sock.bind((interface, 0))
            sock.settimeout(1.0)
            
            while self.running:
                try:
                    packet, addr = sock.recvfrom(65536)
                    self._process_packet_raw(packet, interface)
                    self.stats['packets_captured'] += 1
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        self.logger.debug(f"Packet capture error: {e}")
                        
        except Exception as e:
            self.logger.error(f"Error setting up raw socket on {interface}: {e}")
    
    def _process_packet_scapy(self, packet, interface: str):
        """Process packet using Scapy"""
        if not packet.haslayer(IP):
            return
        
        ip_layer = packet[IP]
        
        # Extract basic info
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto
        
        # Process based on protocol
        if packet.haslayer(TCP) and 'tcp' in self.protocols:
            tcp_layer = packet[TCP]
            self._process_tcp_flow(
                src_ip, dst_ip, tcp_layer.sport, tcp_layer.dport,
                len(packet), tcp_layer.flags, interface
            )
        elif packet.haslayer(UDP) and 'udp' in self.protocols:
            udp_layer = packet[UDP]
            self._process_udp_flow(
                src_ip, dst_ip, udp_layer.sport, udp_layer.dport,
                len(packet), interface
            )
        elif packet.haslayer(ICMP) and 'icmp' in self.protocols:
            icmp_layer = packet[ICMP]
            self._process_icmp_flow(
                src_ip, dst_ip, icmp_layer.type, icmp_layer.code,
                len(packet), interface
            )
    
    def _process_packet_raw(self, packet: bytes, interface: str):
        """Process raw packet data"""
        try:
            # Parse Ethernet header (14 bytes)
            if len(packet) < 14:
                return
            
            eth_header = struct.unpack('!6s6sH', packet[:14])
            eth_type = eth_header[2]
            
            # Check if IP packet (0x0800)
            if eth_type != 0x0800:
                return
            
            # Parse IP header
            if len(packet) < 34:
                return
            
            ip_header = struct.unpack('!BBHHHBBH4s4s', packet[14:34])
            
            version_ihl = ip_header[0]
            ihl = (version_ihl & 0xF) * 4
            protocol = ip_header[6]
            src_ip = socket.inet_ntoa(ip_header[8])
            dst_ip = socket.inet_ntoa(ip_header[9])
            
            # Process transport layer
            transport_offset = 14 + ihl
            
            if protocol == 6 and 'tcp' in self.protocols:  # TCP
                self._process_tcp_raw(packet, transport_offset, src_ip, dst_ip, interface)
            elif protocol == 17 and 'udp' in self.protocols:  # UDP
                self._process_udp_raw(packet, transport_offset, src_ip, dst_ip, interface)
            elif protocol == 1 and 'icmp' in self.protocols:  # ICMP
                self._process_icmp_raw(packet, transport_offset, src_ip, dst_ip, interface)
                
        except Exception as e:
            self.logger.debug(f"Error parsing raw packet: {e}")
    
    def _process_tcp_raw(self, packet: bytes, offset: int, src_ip: str, dst_ip: str, interface: str):
        """Process raw TCP packet"""
        if len(packet) < offset + 20:
            return
        
        tcp_header = struct.unpack('!HHLLBBHHH', packet[offset:offset+20])
        src_port = tcp_header[0]
        dst_port = tcp_header[1]
        flags = tcp_header[5]
        
        self._process_tcp_flow(
            src_ip, dst_ip, src_port, dst_port,
            len(packet), flags, interface
        )
    
    def _process_udp_raw(self, packet: bytes, offset: int, src_ip: str, dst_ip: str, interface: str):
        """Process raw UDP packet"""
        if len(packet) < offset + 8:
            return
        
        udp_header = struct.unpack('!HHHH', packet[offset:offset+8])
        src_port = udp_header[0]
        dst_port = udp_header[1]
        
        self._process_udp_flow(
            src_ip, dst_ip, src_port, dst_port,
            len(packet), interface
        )
    
    def _process_icmp_raw(self, packet: bytes, offset: int, src_ip: str, dst_ip: str, interface: str):
        """Process raw ICMP packet"""
        if len(packet) < offset + 8:
            return
        
        icmp_header = struct.unpack('!BBHHH', packet[offset:offset+8])
        icmp_type = icmp_header[0]
        icmp_code = icmp_header[1]
        
        self._process_icmp_flow(
            src_ip, dst_ip, icmp_type, icmp_code,
            len(packet), interface
        )
    
    def _process_tcp_flow(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                         packet_size: int, flags: int, interface: str):
        """Process TCP flow"""
        flow_id = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
        current_time = time.time()
        
        # Parse TCP flags
        flag_names = []
        if flags & 0x01: flag_names.append('FIN')
        if flags & 0x02: flag_names.append('SYN')
        if flags & 0x04: flag_names.append('RST')
        if flags & 0x08: flag_names.append('PSH')
        if flags & 0x10: flag_names.append('ACK')
        if flags & 0x20: flag_names.append('URG')
        
        # Update or create flow
        if flow_id in self.active_flows:
            flow = self.active_flows[flow_id]
            flow.last_seen = current_time
            flow.packets_sent += 1
            flow.bytes_sent += packet_size
            flow.flags.extend(flag_names)
        else:
            flow = NetworkFlow(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol='tcp',
                start_time=current_time,
                last_seen=current_time,
                bytes_sent=packet_size,
                packets_sent=1,
                flags=flag_names
            )
            self.active_flows[flow_id] = flow
            self.stats['flows_tracked'] += 1
        
        # Check for suspicious patterns
        self._analyze_tcp_flow(flow, interface)
    
    def _process_udp_flow(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                         packet_size: int, interface: str):
        """Process UDP flow"""
        flow_id = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
        current_time = time.time()
        
        # Update or create flow
        if flow_id in self.active_flows:
            flow = self.active_flows[flow_id]
            flow.last_seen = current_time
            flow.packets_sent += 1
            flow.bytes_sent += packet_size
        else:
            flow = NetworkFlow(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol='udp',
                start_time=current_time,
                last_seen=current_time,
                bytes_sent=packet_size,
                packets_sent=1,
                flags=[]
            )
            self.active_flows[flow_id] = flow
            self.stats['flows_tracked'] += 1
        
        # Check for suspicious patterns
        self._analyze_udp_flow(flow, interface)
    
    def _process_icmp_flow(self, src_ip: str, dst_ip: str, icmp_type: int, icmp_code: int,
                          packet_size: int, interface: str):
        """Process ICMP flow"""
        flow_id = f"{src_ip}->{dst_ip}:icmp:{icmp_type}:{icmp_code}"
        current_time = time.time()
        
        # Create event for ICMP traffic
        event = SecurityEvent(
            timestamp=current_time,
            source_ip=src_ip,
            event_type='icmp_traffic',
            data={
                'dst_ip': dst_ip,
                'icmp_type': icmp_type,
                'icmp_code': icmp_code,
                'packet_size': packet_size,
                'interface': interface
            },
            source=f"network_monitor:{interface}"
        )
        
        self.event_callback(event)
    
    def _analyze_tcp_flow(self, flow: NetworkFlow, interface: str):
        """Analyze TCP flow for suspicious patterns"""
        current_time = time.time()
        
        # Check for port scanning (SYN without ACK)
        if 'SYN' in flow.flags and 'ACK' not in flow.flags:
            self._check_port_scan(flow.src_ip, current_time, interface)
        
        # Check for connection rate anomalies
        self._check_connection_rate(flow.src_ip, flow.dst_port, current_time, interface)
        
        # Check for large data transfers
        if flow.bytes_sent > 1073741824:  # 1GB
            self._generate_network_alert(
                'large_data_transfer',
                flow.src_ip,
                {
                    'dst_ip': flow.dst_ip,
                    'dst_port': flow.dst_port,
                    'bytes_sent': flow.bytes_sent,
                    'duration': current_time - flow.start_time,
                    'interface': interface
                },
                'medium'
            )
    
    def _analyze_udp_flow(self, flow: NetworkFlow, interface: str):
        """Analyze UDP flow for suspicious patterns"""
        current_time = time.time()
        
        # Check for UDP flood
        if flow.packets_sent > 1000 and (current_time - flow.start_time) < 60:
            self._generate_network_alert(
                'udp_flood',
                flow.src_ip,
                {
                    'dst_ip': flow.dst_ip,
                    'dst_port': flow.dst_port,
                    'packets_sent': flow.packets_sent,
                    'duration': current_time - flow.start_time,
                    'interface': interface
                },
                'high'
            )
    
    def _check_port_scan(self, src_ip: str, timestamp: float, interface: str):
        """Check if source IP is performing port scanning"""
        window_start = timestamp - 60  # 1 minute window
        
        # Count unique ports accessed by this IP
        unique_ports = set()
        connection_count = 0
        
        for flow in self.active_flows.values():
            if (flow.src_ip == src_ip and 
                flow.start_time >= window_start and
                flow.protocol == 'tcp'):
                unique_ports.add(flow.dst_port)
                connection_count += 1
        
        # Trigger alert if thresholds exceeded
        if len(unique_ports) >= 10 and connection_count >= 20:
            self._generate_network_alert(
                'port_scan_detected',
                src_ip,
                {
                    'unique_ports': len(unique_ports),
                    'connection_count': connection_count,
                    'time_window': 60,
                    'interface': interface
                },
                'medium'
            )
    
    def _check_connection_rate(self, src_ip: str, dst_port: int, timestamp: float, interface: str):
        """Check connection rate for anomalies"""
        window_start = timestamp - 300  # 5 minute window
        
        # Count connections from this IP
        connection_count = 0
        for flow in self.active_flows.values():
            if (flow.src_ip == src_ip and 
                flow.start_time >= window_start):
                connection_count += 1
        
        # Check threshold
        if connection_count > 100:
            self._generate_network_alert(
                'high_connection_rate',
                src_ip,
                {
                    'connection_count': connection_count,
                    'time_window': 300,
                    'interface': interface
                },
                'medium'
            )
    
    def _flow_analysis_loop(self):
        """Periodic flow analysis and cleanup"""
        while self.running:
            try:
                current_time = time.time()
                
                # Clean up old flows
                expired_flows = []
                for flow_id, flow in self.active_flows.items():
                    if current_time - flow.last_seen > 300:  # 5 minutes
                        expired_flows.append(flow_id)
                
                for flow_id in expired_flows:
                    del self.active_flows[flow_id]
                
                # Log statistics
                if len(self.active_flows) > 0:
                    self.logger.debug(f"Active flows: {len(self.active_flows)}")
                
                time.sleep(60)  # Run every minute
                
            except Exception as e:
                self.logger.error(f"Error in flow analysis: {e}")
                time.sleep(30)
    
    def _generate_network_alert(self, alert_type: str, src_ip: str, details: Dict[str, Any], severity: str):
        """Generate network-based security alert"""
        event = SecurityEvent(
            timestamp=time.time(),
            source_ip=src_ip,
            event_type=alert_type,
            data=details,
            severity=severity,
            source="network_monitor"
        )
        
        self.event_callback(event)
        self.stats['alerts_generated'] += 1
    
    def get_stats(self) -> Dict[str, Any]:
        """Get network monitoring statistics"""
        return {
            'packets_captured': self.stats['packets_captured'],
            'active_flows': len(self.active_flows),
            'flows_tracked': self.stats['flows_tracked'],
            'alerts_generated': self.stats['alerts_generated'],
            'interfaces_monitored': len(self.capture_threads)
        }