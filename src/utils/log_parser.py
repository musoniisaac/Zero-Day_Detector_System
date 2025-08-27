#!/usr/bin/env python3
"""
Log Parser Module
Multi-format log parsing with normalized output
"""

import re
import time
import logging
from typing import Dict, Any, Optional
from datetime import datetime
from enum import Enum


class LogFormat(Enum):
    """Supported log formats"""
    SYSLOG = "syslog"
    APACHE = "apache"
    NGINX = "nginx"
    IIS = "iis"
    JSON = "json"


class LogParser:
    """Multi-format log parser"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Compiled regex patterns for performance
        self.patterns = self._compile_patterns()
    
    def parse_log_line(self, line: str, format_type: LogFormat) -> Optional[Dict[str, Any]]:
        """Parse a single log line based on format type"""
        if not line or not line.strip():
            return None
        
        try:
            if format_type == LogFormat.SYSLOG:
                return self._parse_syslog(line.strip())
            elif format_type == LogFormat.APACHE:
                return self._parse_apache(line.strip())
            elif format_type == LogFormat.NGINX:
                return self._parse_apache(line.strip())  # Similar format
            elif format_type == LogFormat.IIS:
                return self._parse_iis(line.strip())
            elif format_type == LogFormat.JSON:
                return self._parse_json(line.strip())
            else:
                self.logger.warning(f"Unsupported log format: {format_type}")
                return None
                
        except Exception as e:
            self.logger.debug(f"Error parsing log line: {e}")
            return None
    
    def _compile_patterns(self) -> Dict[str, re.Pattern]:
        """Compile regex patterns for log formats"""
        return {
            'syslog': re.compile(
                r'^(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+'
                r'(?P<hostname>\S+)\s+'
                r'(?P<program>\S+?)(?:\[(?P<pid>\d+)\])?\s*:\s*'
                r'(?P<message>.*)$'
            ),
            'syslog_with_priority': re.compile(
                r'^<(?P<priority>\d+)>'
                r'(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+'
                r'(?P<hostname>\S+)\s+'
                r'(?P<program>\S+?)(?:\[(?P<pid>\d+)\])?\s*:\s*'
                r'(?P<message>.*)$'
            ),
            'apache_common': re.compile(
                r'^(?P<client_ip>\S+)\s+'
                r'(?P<ident>\S+)\s+'
                r'(?P<user>\S+)\s+'
                r'\[(?P<timestamp>[^\]]+)\]\s+'
                r'"(?P<method>\S+)\s+(?P<url>\S+)\s+(?P<protocol>[^"]+)"\s+'
                r'(?P<status>\d+)\s+'
                r'(?P<bytes>\S+)'
            ),
            'apache_combined': re.compile(
                r'^(?P<client_ip>\S+)\s+'
                r'(?P<ident>\S+)\s+'
                r'(?P<user>\S+)\s+'
                r'\[(?P<timestamp>[^\]]+)\]\s+'
                r'"(?P<method>\S+)\s+(?P<url>\S+)\s+(?P<protocol>[^"]+)"\s+'
                r'(?P<status>\d+)\s+'
                r'(?P<bytes>\S+)\s+'
                r'"(?P<referer>[^"]*)"\s+'
                r'"(?P<user_agent>[^"]*)"'
            ),
            'ssh_auth': re.compile(
                r'(?P<auth_type>Failed|Accepted)\s+(?P<method>\w+)\s+for\s+'
                r'(?P<user>\S+)\s+from\s+(?P<client_ip>\S+)\s+port\s+(?P<port>\d+)'
            ),
            'sudo_command': re.compile(
                r'(?P<user>\S+)\s*:\s*TTY=(?P<tty>\S+)\s*;\s*PWD=(?P<pwd>\S+)\s*;\s*'
                r'USER=(?P<target_user>\S+)\s*;\s*COMMAND=(?P<command>.*)'
            )
        }
    
    def _parse_syslog(self, line: str) -> Dict[str, Any]:
        """Parse syslog format"""
        # Try with priority first
        match = self.patterns['syslog_with_priority'].match(line)
        if match:
            groups = match.groupdict()
            priority = int(groups.get('priority', 0))
            facility = priority >> 3
            severity = priority & 7
        else:
            # Try without priority
            match = self.patterns['syslog'].match(line)
            if not match:
                return None
            groups = match.groupdict()
            facility = 16  # local0
            severity = 6   # info
        
        # Parse timestamp
        timestamp = self._parse_timestamp(groups.get('timestamp', ''))
        
        # Extract additional information from message
        message = groups.get('message', '')
        program = groups.get('program', '')
        
        result = {
            'timestamp': timestamp,
            'hostname': groups.get('hostname', ''),
            'program': program,
            'pid': groups.get('pid'),
            'message': message,
            'facility': facility,
            'severity': severity,
            'raw_line': line
        }
        
        # Parse specific program messages
        if program == 'sshd':
            ssh_match = self.patterns['ssh_auth'].search(message)
            if ssh_match:
                ssh_data = ssh_match.groupdict()
                result.update({
                    'auth_result': ssh_data.get('auth_type'),
                    'auth_method': ssh_data.get('method'),
                    'username': ssh_data.get('user'),
                    'client_ip': ssh_data.get('client_ip'),
                    'client_port': ssh_data.get('port')
                })
        elif program == 'sudo':
            sudo_match = self.patterns['sudo_command'].search(message)
            if sudo_match:
                sudo_data = sudo_match.groupdict()
                result.update({
                    'sudo_user': sudo_data.get('user'),
                    'sudo_tty': sudo_data.get('tty'),
                    'sudo_pwd': sudo_data.get('pwd'),
                    'sudo_target_user': sudo_data.get('target_user'),
                    'sudo_command': sudo_data.get('command')
                })
        
        return result
    
    def _parse_apache(self, line: str) -> Dict[str, Any]:
        """Parse Apache/Nginx access log format"""
        # Try combined format first
        match = self.patterns['apache_combined'].match(line)
        if not match:
            # Try common format
            match = self.patterns['apache_common'].match(line)
            if not match:
                return None
        
        groups = match.groupdict()
        
        # Parse timestamp
        timestamp = self._parse_timestamp(groups.get('timestamp', ''))
        
        # Parse status and bytes
        status_code = int(groups.get('status', 0))
        bytes_sent = groups.get('bytes', '0')
        if bytes_sent == '-':
            bytes_sent = 0
        else:
            bytes_sent = int(bytes_sent)
        
        result = {
            'timestamp': timestamp,
            'client_ip': groups.get('client_ip', ''),
            'ident': groups.get('ident', ''),
            'user': groups.get('user', ''),
            'method': groups.get('method', ''),
            'url': groups.get('url', ''),
            'protocol': groups.get('protocol', ''),
            'status_code': status_code,
            'bytes_sent': bytes_sent,
            'referer': groups.get('referer', ''),
            'user_agent': groups.get('user_agent', ''),
            'raw_line': line
        }
        
        return result
    
    def _parse_iis(self, line: str) -> Dict[str, Any]:
        """Parse IIS W3C Extended Log Format"""
        if line.startswith('#'):
            return None  # Skip header lines
        
        fields = line.split(' ')
        
        if len(fields) < 10:
            return None
        
        # Parse timestamp
        timestamp_str = f"{fields[0]} {fields[1]}" if len(fields) > 1 else fields[0]
        timestamp = self._parse_timestamp(timestamp_str)
        
        result = {
            'timestamp': timestamp,
            'server_ip': fields[2] if len(fields) > 2 else '',
            'method': fields[3] if len(fields) > 3 else '',
            'uri_stem': fields[4] if len(fields) > 4 else '',
            'uri_query': fields[5] if len(fields) > 5 else '',
            'server_port': int(fields[6]) if len(fields) > 6 and fields[6] != '-' else 0,
            'username': fields[7] if len(fields) > 7 and fields[7] != '-' else '',
            'client_ip': fields[8] if len(fields) > 8 else '',
            'user_agent': fields[9] if len(fields) > 9 else '',
            'status_code': int(fields[10]) if len(fields) > 10 and fields[10] != '-' else 0,
            'bytes_sent': int(fields[11]) if len(fields) > 11 and fields[11] != '-' else 0,
            'raw_line': line
        }
        
        return result
    
    def _parse_json(self, line: str) -> Dict[str, Any]:
        """Parse JSON log format"""
        import json
        
        try:
            data = json.loads(line)
            
            # Ensure timestamp is present
            if 'timestamp' not in data:
                data['timestamp'] = time.time()
            else:
                # Try to parse timestamp if it's a string
                if isinstance(data['timestamp'], str):
                    data['timestamp'] = self._parse_timestamp(data['timestamp'])
            
            data['raw_line'] = line
            return data
            
        except json.JSONDecodeError:
            return None
    
    def _parse_timestamp(self, timestamp_str: str) -> float:
        """Convert timestamp string to Unix timestamp"""
        if not timestamp_str:
            return time.time()
        
        # Common timestamp formats
        formats = [
            "%b %d %H:%M:%S",                    # Syslog format: "Jan 15 14:30:22"
            "%d/%b/%Y:%H:%M:%S %z",              # Apache format: "15/Jan/2025:14:30:22 +0000"
            "%d/%b/%Y:%H:%M:%S",                 # Apache without timezone
            "%Y-%m-%d %H:%M:%S",                 # IIS format: "2025-01-15 14:30:22"
            "%Y-%m-%dT%H:%M:%S.%fZ",             # ISO format: "2025-01-15T14:30:22.123Z"
            "%Y-%m-%dT%H:%M:%SZ",                # ISO format without microseconds
            "%Y-%m-%dT%H:%M:%S%z",               # ISO format with timezone
        ]
        
        for fmt in formats:
            try:
                # Handle timezone info
                if '%z' in fmt:
                    dt = datetime.strptime(timestamp_str, fmt)
                else:
                    dt = datetime.strptime(timestamp_str, fmt)
                    # Assume current year if not specified
                    if dt.year == 1900:
                        dt = dt.replace(year=datetime.now().year)
                
                return dt.timestamp()
                
            except ValueError:
                continue
        
        # If no format matches, try to extract just the time part
        time_match = re.search(r'(\d{2}:\d{2}:\d{2})', timestamp_str)
        if time_match:
            try:
                time_str = time_match.group(1)
                today = datetime.now().date()
                dt = datetime.combine(today, datetime.strptime(time_str, "%H:%M:%S").time())
                return dt.timestamp()
            except ValueError:
                pass
        
        # If all else fails, return current time
        return time.time()