# Zero-Day Detector System

A lightweight, real-time security monitoring solution for Linux systems that identifies and alerts on potential zero-day attacks and advanced persistent threats using behavioral analysis and statistical anomaly detection.

## Overview
This project provides a comprehensive security monitoring system designed to detect unknown threats and suspicious activities in real-time. The system combines rule-based detection with statistical analysis to identify potential security breaches before they cause significant damage.

## Features

### Core Features
- **Real-time Log Monitoring**: Continuously monitors system logs including authentication logs, system logs, and web server logs with sub-second response times
- **Network Traffic Analysis**: Captures and analyzes network packets to detect suspicious connection patterns, port scans, and data exfiltration attempts
- **Rule-based Detection Engine**: Flexible, configurable detection patterns for known attack vectors with support for custom rules and conditions
- **Statistical Anomaly Detection**: Uses sliding window algorithms and Z-score analysis to identify deviations from normal behavior patterns

### Advanced Features
- **Multi-threaded Processing**: Parallel event processing with configurable worker threads for optimal performance
- **Dynamic Baseline Establishment**: Automatically learns normal system behavior over time and adjusts detection thresholds accordingly
- **Multi-channel Alert System**: Supports email, syslog, file logging, and webhook notifications with severity-based routing
- **Performance Optimization**: Maintains <5% CPU usage and <512MB RAM consumption while processing 10,000+ events per second

## Installation

### Prerequisites
- Linux system (Ubuntu 18.04+, CentOS 7+, or RHEL 7+)
- Python 3.6 or higher
- Root privileges for installation
- Network interface access for packet capture
- libpcap development libraries
- Build tools (gcc, make)

### Setup Instructions
```bash
# Download and extract the package
wget https://github.com/zdd-security/detector/releases/download/v2.1.0/zdd-linux-amd64.tar.gz
tar -xzf zdd-linux-amd64.tar.gz
cd zdd-linux-amd64

# Run the automated installation script
sudo ./scripts/install.sh

# Or install dependencies manually
sudo apt update
sudo apt install -y python3 python3-pip python3-dev libpcap-dev build-essential

# Install Python dependencies
pip3 install -r requirements.txt
```

## Available Commands

### Basic Commands
```bash
# Start the detector service
sudo systemctl start zdd-detector

# Stop the detector service
sudo systemctl stop zdd-detector

# Check service status
sudo systemctl status zdd-detector

# View real-time logs
sudo journalctl -u zdd-detector -f
```

### Development Commands
```bash
# Run in foreground with debug logging
sudo python3 src/main.py --log-level DEBUG

# Validate configuration
zdd-config validate

# Test detection rules
zdd-config test-rules

# Perform health check
zdd-config health-check
```

## Tools and Utilities

### Built-in Tools
- **zdd-detector**: Main detection daemon that runs as a system service
- **zdd-config**: Configuration validation and management utility
- **zdd-admin**: Administrative tool for service management and monitoring

### External Integrations
- **SIEM Integration**: Forwards alerts to Security Information and Event Management systems via syslog
- **Email Notifications**: SMTP integration for critical alert notifications
- **Webhook Support**: HTTP POST integration for custom alert handling systems
- **Log Aggregation**: Compatible with ELK stack, Splunk, and other log analysis platforms

## Configuration

### Environment Variables
```env
# Optional environment variables
ZDD_CONFIG_PATH=/etc/zdd
ZDD_LOG_LEVEL=INFO
ZDD_WORKER_THREADS=4
PYTHONPATH=/usr/local/lib/zdd
```

### Configuration Files
- `config.yaml`: Main system configuration including data sources, detection rules, and alert settings
- `rules/*.yaml`: Individual detection rule definitions organized by category
- `logging.yaml`: Logging configuration and output settings

## Usage Examples

### Basic Usage
```python
# Example: Creating a custom detection rule
rule = {
    "rule_id": "custom_ssh_monitor",
    "name": "Custom SSH Monitoring",
    "category": "authentication",
    "severity": "medium",
    "conditions": {
        "failed_attempts": {
            "type": "frequency",
            "threshold": 3,
            "time_window": 300
        }
    }
}
```

### Advanced Usage
```python
# Example: Statistical anomaly detection configuration
statistics_config = {
    "baseline_window_hours": 168,  # 7 days
    "anomaly_sensitivity": "high",
    "min_baseline_samples": 50,
    "metrics": ["connection_rate", "failed_logins", "data_transfer"]
}
```

## API Reference

### Configuration Endpoints
- **Rule Management**: Add, modify, and remove detection rules dynamically
- **Threshold Adjustment**: Update statistical analysis parameters
- **Alert Configuration**: Modify notification channels and severity routing

### Monitoring Endpoints
- **System Status**: Current system health and performance metrics
- **Alert History**: Recent alerts and their details
- **Statistics**: Current baselines and anomaly detection statistics

## Troubleshooting

### Common Issues
1. **Permission Denied for Packet Capture**: Ensure the service user has CAP_NET_RAW capability or run with appropriate privileges
2. **Log Files Not Accessible**: Add the zdd-detector user to the adm group and verify file permissions
3. **High CPU Usage**: Check for excessive detection rules or reduce worker thread count
4. **Service Won't Start**: Validate configuration files and check system logs for detailed error messages

### Error Codes
- `CONFIG_001`: Invalid configuration file format or missing required sections
- `NETWORK_002`: Unable to bind to network interface for packet capture
- `RULE_003`: Detection rule compilation failed due to invalid syntax
- `ALERT_004`: Alert delivery failed due to misconfigured notification channels

## Detection Capabilities

### Network Anomalies
- Port scanning detection with configurable thresholds
- DDoS attack identification based on traffic patterns
- Unusual outbound connections and data exfiltration attempts
- Connection rate anomalies and suspicious traffic flows

### System Behavior Analysis
- Authentication anomalies and brute force attack detection
- Privilege escalation attempts and suspicious sudo usage
- Process execution pattern analysis
- File system access violations and integrity monitoring

### Statistical Analysis Features
- Sliding window baseline establishment over configurable time periods
- Z-score anomaly detection with multiple sensitivity levels
- Percentile-based threshold calculation
- Trend analysis for identifying gradual changes in behavior

## Performance Specifications

### Resource Requirements
- **CPU Usage**: Less than 5% under normal load conditions
- **Memory Usage**: Maximum 512MB RAM consumption including caches
- **Detection Latency**: Sub-second alert generation response time
- **Throughput**: Processes 10,000+ log events per second
- **Storage**: Minimal disk I/O impact with configurable data retention

### Scalability
- **Horizontal Scaling**: Multi-node deployment across network segments
- **Vertical Scaling**: Linear performance scaling up to 8 CPU cores
- **Load Distribution**: Round-robin event distribution across worker threads
- **Data Aggregation**: Centralized alert collection from multiple sensors

## Contributing
We welcome contributions to improve the Zero-Day Detector system. Please follow these guidelines:

1. Fork the repository and create a feature branch
2. Ensure all tests pass and add new tests for your changes
3. Follow the existing code style and documentation standards
4. Submit a pull request with a clear description of your changes

## License
This project is licensed under the MIT License. See the LICENSE file for full license text.

## Support
For support, bug reports, and feature requests:

- **GitHub Issues**: https://github.com/zdd-security/detector/issues
- **Documentation**: https://docs.zdd-security.com
- **Email Support**: support@zdd-security.com
- **Community Forum**: https://community.zdd-security.com

For enterprise support and custom implementations, please contact our professional services team.