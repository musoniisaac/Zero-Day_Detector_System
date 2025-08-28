#!/usr/bin/env python3
"""
Zero-Day Detector System - Main Entry Point
Lightweight real-time security monitoring for Linux systems
Created by Isaac Musoni
"""

import sys
import os
import signal
import time
import argparse
import logging
from pathlib import Path

# Add src directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.detector import ZeroDayDetector
from core.config import ConfigManager
from monitors.pcap_analyzer import PcapAnalyzer
from utils.logger import setup_logging


def signal_handler(signum, frame):
    """Handle shutdown signals gracefully"""
    print(f"\nReceived signal {signum}, shutting down...")
    if hasattr(signal_handler, 'detector'):
        signal_handler.detector.stop()
    sys.exit(0)


def analyze_pcap_mode(args):
    """Run in PCAP analysis mode"""
    from core.config import ConfigManager
    
    # Load configuration
    config_manager = ConfigManager(args.config)
    config = config_manager.load_config()
    
    # Create event callback for collecting results
    events = []
    def event_callback(event):
        events.append(event)
    
    # Initialize PCAP analyzer
    pcap_config = config.get('pcap_analysis', {})
    analyzer = PcapAnalyzer(pcap_config, event_callback)
    
    logger = logging.getLogger(__name__)
    
    try:
        if args.pcap_file:
            # Analyze single file
            logger.info(f"Analyzing PCAP file: {args.pcap_file}")
            result = analyzer.analyze_pcap_file(
                args.pcap_file, 
                time_acceleration=args.time_acceleration
            )
            results = [result]
        elif args.pcap_directory:
            # Analyze directory
            logger.info(f"Analyzing PCAP directory: {args.pcap_directory}")
            results = analyzer.analyze_pcap_directory(
                args.pcap_directory,
                pattern=args.pcap_pattern
            )
        else:
            logger.error("Either --pcap-file or --pcap-directory must be specified")
            return 1
        
        # Print summary
        total_packets = sum(r.total_packets for r in results)
        total_events = sum(r.events_generated for r in results)
        total_flows = sum(r.flows_detected for r in results)
        
        logger.info(f"PCAP Analysis Complete:")
        logger.info(f"  Files analyzed: {len(results)}")
        logger.info(f"  Total packets: {total_packets:,}")
        logger.info(f"  Events generated: {total_events}")
        logger.info(f"  Flows detected: {total_flows}")
        
        # Export results if requested
        if args.output_file:
            analyzer.export_results(args.output_file, results)
        
        # Print events if verbose
        if args.verbose and events:
            logger.info(f"\nGenerated Events:")
            for event in events[-10:]:  # Show last 10 events
                logger.info(f"  {event.timestamp}: {event.event_type} from {event.source_ip}")
        
        return 0
        
    except Exception as e:
        logger.error(f"PCAP analysis failed: {e}")
        return 1


def main():
    """Main entry point for Zero-Day Detector"""
    parser = argparse.ArgumentParser(description='Zero-Day Detector System')
    parser.add_argument('--config', '-c', default='/etc/zdd/config.yaml',
                       help='Configuration file path')
    parser.add_argument('--daemon', '-d', action='store_true',
                       help='Run as daemon')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                       default='INFO', help='Logging level')
    parser.add_argument('--validate-config', action='store_true',
                       help='Validate configuration and exit')
    
    # PCAP analysis options
    parser.add_argument('--pcap-mode', action='store_true',
                       help='Run in PCAP analysis mode')
    parser.add_argument('--pcap-file', type=str,
                       help='PCAP file to analyze')
    parser.add_argument('--pcap-directory', type=str,
                       help='Directory containing PCAP files to analyze')
    parser.add_argument('--pcap-pattern', type=str, default='*.pcap',
                       help='File pattern for PCAP files (default: *.pcap)')
    parser.add_argument('--time-acceleration', type=float, default=float('inf'),
                       help='Time acceleration factor (1.0=real-time, inf=max speed)')
    parser.add_argument('--output-file', type=str,
                       help='Output file for analysis results (JSON format)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output')
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.log_level)
    logger = logging.getLogger(__name__)
    
    # Handle PCAP analysis mode
    if args.pcap_mode:
        return analyze_pcap_mode(args)
    
    try:
        # Load configuration
        config_manager = ConfigManager(args.config)
        config = config_manager.load_config()
        
        if args.validate_config:
            logger.info("Configuration validation successful")
            return 0
        
        # Initialize detector
        detector = ZeroDayDetector(config)
        signal_handler.detector = detector
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        logger.info("Starting Zero-Day Detector System v2.1.0")
        logger.info(f"Configuration loaded from: {args.config}")
        
        # Start the detector
        detector.start()
        
        # Keep main thread alive
        try:
            while detector.is_running():
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Received keyboard interrupt")
        
        # Graceful shutdown
        logger.info("Shutting down Zero-Day Detector...")
        detector.stop()
        logger.info("Shutdown complete")
        
        return 0
        
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())