#!/usr/bin/env python3
"""
Log Monitor
Real-time system log monitoring and parsing
Created by Isaac Musoni
"""

import os
import time
import threading
import logging
from typing import Dict, List, Any, Callable, Optional
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from core.detector import SecurityEvent
from utils.log_parser import LogParser, LogFormat


class LogFileHandler(FileSystemEventHandler):
    """Handle log file changes"""
    
    def __init__(self, log_monitor):
        self.log_monitor = log_monitor
        self.logger = logging.getLogger(__name__)
    
    def on_modified(self, event):
        """Handle file modification events"""
        if event.is_directory:
            return
        
        file_path = Path(event.src_path)
        if file_path in self.log_monitor.monitored_files:
            self.log_monitor._process_file_changes(file_path)


class LogMonitor:
    """System log monitoring component"""
    
    def __init__(self, config: Dict[str, Any], event_callback: Callable):
        self.config = config
        self.event_callback = event_callback
        self.logger = logging.getLogger(__name__)
        
        # Initialize parser
        self.parser = LogParser()
        
        # File monitoring
        self.monitored_files = {}
        self.file_positions = {}
        self.observer = Observer()
        
        # Threading
        self.running = False
        self.monitor_thread = None
        
        # Setup monitored files
        self._setup_monitored_files()
    
    def _setup_monitored_files(self):
        """Setup files to monitor"""
        log_paths = self.config.get('paths', [])
        
        for path_str in log_paths:
            path = Path(path_str)
            
            if path.exists() and path.is_file():
                # Determine log format
                log_format = self._detect_log_format(path)
                
                self.monitored_files[path] = {
                    'format': log_format,
                    'last_size': path.stat().st_size,
                    'last_inode': path.stat().st_ino
                }
                
                # Initialize file position to end of file
                self.file_positions[path] = path.stat().st_size
                
                self.logger.info(f"Monitoring log file: {path} (format: {log_format.value})")
            else:
                self.logger.warning(f"Log file not found: {path}")
    
    def _detect_log_format(self, file_path: Path) -> LogFormat:
        """Detect log format based on file path and content"""
        path_str = str(file_path).lower()
        
        if 'apache' in path_str or 'access.log' in path_str:
            return LogFormat.APACHE
        elif 'nginx' in path_str:
            return LogFormat.APACHE  # Nginx uses similar format
        elif 'auth.log' in path_str or 'syslog' in path_str:
            return LogFormat.SYSLOG
        else:
            # Try to detect from content
            try:
                with open(file_path, 'r') as f:
                    # Read last few lines
                    lines = f.readlines()[-5:]
                    
                for line in lines:
                    if line.strip():
                        # Check for syslog pattern
                        if ' ' in line and ':' in line:
                            return LogFormat.SYSLOG
                        # Check for Apache pattern
                        elif '[' in line and ']' in line and '"' in line:
                            return LogFormat.APACHE
                        
            except Exception:
                pass
        
        return LogFormat.SYSLOG  # Default
    
    def start(self):
        """Start log monitoring"""
        if self.running:
            return
        
        self.running = True
        
        # Start file system observer
        for file_path in self.monitored_files.keys():
            self.observer.schedule(
                LogFileHandler(self),
                str(file_path.parent),
                recursive=False
            )
        
        self.observer.start()
        
        # Start monitoring thread
        self.monitor_thread = threading.Thread(
            target=self._monitor_loop,
            name="LogMonitor",
            daemon=True
        )
        self.monitor_thread.start()
        
        self.logger.info(f"Log monitor started, watching {len(self.monitored_files)} files")
    
    def stop(self):
        """Stop log monitoring"""
        if not self.running:
            return
        
        self.running = False
        
        # Stop observer
        self.observer.stop()
        self.observer.join()
        
        # Wait for monitor thread
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5.0)
        
        self.logger.info("Log monitor stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        poll_interval = self.config.get('poll_interval', 1.0)
        
        while self.running:
            try:
                # Check each monitored file
                for file_path in list(self.monitored_files.keys()):
                    self._check_file_changes(file_path)
                
                time.sleep(poll_interval)
                
            except Exception as e:
                self.logger.error(f"Error in monitor loop: {e}")
                time.sleep(5.0)
    
    def _check_file_changes(self, file_path: Path):
        """Check for changes in a log file"""
        try:
            if not file_path.exists():
                return
            
            stat = file_path.stat()
            file_info = self.monitored_files[file_path]
            
            # Check if file was rotated (inode changed)
            if stat.st_ino != file_info['last_inode']:
                self.logger.info(f"Log rotation detected: {file_path}")
                self.file_positions[file_path] = 0
                file_info['last_inode'] = stat.st_ino
            
            # Check if file grew
            current_size = stat.st_size
            if current_size > file_info['last_size']:
                self._read_new_lines(file_path, file_info['last_size'], current_size)
                file_info['last_size'] = current_size
            elif current_size < file_info['last_size']:
                # File was truncated
                self.logger.info(f"Log file truncated: {file_path}")
                self.file_positions[file_path] = 0
                file_info['last_size'] = current_size
                
        except Exception as e:
            self.logger.error(f"Error checking file {file_path}: {e}")
    
    def _process_file_changes(self, file_path: Path):
        """Process file changes from watchdog"""
        self._check_file_changes(file_path)
    
    def _read_new_lines(self, file_path: Path, start_pos: int, end_pos: int):
        """Read new lines from log file"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                f.seek(start_pos)
                
                while f.tell() < end_pos:
                    line = f.readline()
                    if not line:
                        break
                    
                    self._process_log_line(file_path, line.strip())
                    
        except Exception as e:
            self.logger.error(f"Error reading file {file_path}: {e}")
    
    def _process_log_line(self, file_path: Path, line: str):
        """Process a single log line"""
        if not line:
            return
        
        try:
            file_info = self.monitored_files[file_path]
            log_format = file_info['format']
            
            # Parse log line
            parsed_data = self.parser.parse_log_line(line, log_format)
            
            if parsed_data:
                # Create security event
                event = SecurityEvent(
                    timestamp=parsed_data.get('timestamp', time.time()),
                    source_ip=parsed_data.get('client_ip', parsed_data.get('hostname', 'unknown')),
                    event_type='log_entry',
                    data=parsed_data,
                    source=f"log_monitor:{file_path.name}"
                )
                
                # Send to callback
                self.event_callback(event)
                
        except Exception as e:
            self.logger.error(f"Error processing log line from {file_path}: {e}")
            self.logger.debug(f"Problematic line: {line}")