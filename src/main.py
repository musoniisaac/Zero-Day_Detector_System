#!/usr/bin/env python3
"""
Zero-Day Detector System - Main Entry Point
Lightweight real-time security monitoring for Linux systems
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
from utils.logger import setup_logging


def signal_handler(signum, frame):
    """Handle shutdown signals gracefully"""
    print(f"\nReceived signal {signum}, shutting down...")
    if hasattr(signal_handler, 'detector'):
        signal_handler.detector.stop()
    sys.exit(0)


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
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.log_level)
    logger = logging.getLogger(__name__)
    
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