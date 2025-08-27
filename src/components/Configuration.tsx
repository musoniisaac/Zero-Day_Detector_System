import React, { useState } from 'react';
import { Settings, FileText, Code, Database } from 'lucide-react';

export function Configuration() {
  const [configSection, setConfigSection] = useState<'main' | 'rules' | 'logging' | 'network'>('main');

  const configSections = {
    main: {
      title: 'Main Configuration',
      code: `# Zero-Day Detector Main Configuration
# /etc/zdd/config.yaml

system:
  # Performance settings
  max_cpu_usage: 5.0          # Percentage
  max_memory_mb: 512          # Megabytes
  worker_threads: 4           # Processing threads
  
  # Data retention
  log_retention_days: 30
  alert_retention_days: 90
  baseline_retention_days: 180

data_sources:
  # System log monitoring
  system_logs:
    enabled: true
    paths:
      - /var/log/auth.log
      - /var/log/syslog
      - /var/log/apache2/access.log
    formats: [syslog, apache, iis]
  
  # Network monitoring
  network:
    enabled: true
    interfaces: [eth0, wlan0]
    capture_filter: "not broadcast and not multicast"
    protocols: [tcp, udp, icmp]

detection:
  # Statistical analysis settings
  baseline_window_hours: 168   # 7 days
  anomaly_sensitivity: medium  # low, medium, high, very_high
  min_baseline_samples: 100
  
  # Rule engine settings
  rule_update_interval: 300    # seconds
  max_concurrent_rules: 1000
  rule_cache_size_mb: 64`
    },
    rules: {
      title: 'Rule Configuration',
      code: `# Rule Directory Structure
# /etc/zdd/rules/

network/
├── port_scanning.yaml
├── ddos_detection.yaml
├── data_exfiltration.yaml
└── suspicious_connections.yaml

system/
├── authentication.yaml
├── privilege_escalation.yaml
├── process_monitoring.yaml
└── file_integrity.yaml

application/
├── web_attacks.yaml
├── database_attacks.yaml
└── api_abuse.yaml

# Example: Port Scanning Rule
# /etc/zdd/rules/network/port_scanning.yaml

rule_id: "network_port_scan_001"
name: "TCP Port Scanning Detection"
description: "Detects rapid sequential connection attempts"
category: "network"
severity: "medium"
enabled: true

conditions:
  - type: "connection_count"
    source_ip_tracking: true
    thresholds:
      connections_per_minute: 20
      unique_ports_accessed: 10
      time_window: "60s"
  
  - type: "connection_pattern"
    pattern: "syn_scan"
    min_ports: 5
    max_response_time: "1s"

actions:
  - type: "alert"
    channels: ["email", "slack"]
  - type: "log"
    facility: "security"
  - type: "enrich"
    geolocation: true
    threat_intelligence: true`
    },
    logging: {
      title: 'Logging Configuration', 
      code: `# Logging Configuration
# /etc/zdd/logging.yaml

log_level: INFO                # DEBUG, INFO, WARN, ERROR, CRITICAL
max_log_file_size: 100MB      # Rotate at this size
max_log_files: 10             # Keep this many rotated files
log_format: json              # json, text, syslog

outputs:
  file:
    enabled: true
    path: /var/log/zdd/detector.log
    
  syslog:
    enabled: true
    facility: local0
    server: localhost:514
    protocol: udp
    
  console:
    enabled: false            # Disable for production
    colors: true

# Log categories
categories:
  detection:
    level: INFO
    file: /var/log/zdd/detection.log
    
  performance:
    level: WARN  
    file: /var/log/zdd/performance.log
    
  alerts:
    level: INFO
    file: /var/log/zdd/alerts.log
    format: json
    
  debug:
    level: DEBUG
    enabled: false            # Enable for troubleshooting`
    },
    network: {
      title: 'Network Configuration',
      code: `# Network Monitoring Configuration
# /etc/zdd/network.yaml

interfaces:
  # Primary monitoring interface
  - name: eth0
    enabled: true
    promiscuous: false         # Set to true for full packet capture
    buffer_size: 16MB
    
  # WiFi monitoring (if applicable)  
  - name: wlan0
    enabled: false
    promiscuous: false

capture_settings:
  # Packet capture filters (BPF syntax)
  filters:
    - "tcp port 22 or tcp port 80 or tcp port 443"
    - "udp port 53"
    - "icmp"
  
  # Exclude internal management traffic
  exclude_filters:
    - "host 127.0.0.1"
    - "broadcast"
    - "multicast"

protocols:
  tcp:
    enabled: true
    track_connections: true
    connection_timeout: 300s
    
  udp:
    enabled: true
    session_timeout: 60s
    
  icmp:
    enabled: true
    track_types: [0, 3, 8, 11]  # Echo Reply, Unreachable, Echo, Time Exceeded

flow_analysis:
  # Network flow tracking
  flow_timeout: 300s
  max_flows: 100000
  export_interval: 60s
  
  # Geolocation enrichment
  geolocation:
    enabled: true
    database: /var/lib/zdd/GeoLite2-City.mmdb
    
  # Threat intelligence integration
  threat_intel:
    enabled: true
    feeds:
      - name: "emerging_threats"
        url: "https://rules.emergingthreats.net/fwrules/"
        update_interval: 3600s`
    }
  };

  return (
    <div className="space-y-8">
      <div className="bg-white rounded-lg shadow-sm border border-slate-200 p-6">
        <h2 className="text-2xl font-bold text-slate-800 mb-6">Configuration Management</h2>
        
        <div className="mb-6">
          <h3 className="text-xl font-semibold text-slate-700 mb-4">Configuration Structure</h3>
          <p className="text-slate-600 leading-relaxed mb-4">
            The system uses YAML-based configuration files organized in a hierarchical structure. 
            This approach provides flexibility while maintaining readability and version control compatibility.
          </p>
          
          <div className="grid grid-cols-1 md:grid-cols-4 gap-3 mb-6">
            {Object.entries(configSections).map(([key, section]) => (
              <button
                key={key}
                onClick={() => setConfigSection(key as any)}
                className={`p-3 rounded-lg text-left transition-colors ${
                  configSection === key
                    ? 'bg-blue-100 border border-blue-300 text-blue-700'
                    : 'bg-slate-50 border border-slate-200 text-slate-700 hover:bg-slate-100'
                }`}
              >
                <div className="font-medium text-sm">{section.title}</div>
              </button>
            ))}
          </div>

          <div className="bg-slate-900 rounded-lg p-6 text-green-400 font-mono text-sm">
            <div className="flex items-center space-x-2 mb-4">
              <FileText className="h-4 w-4" />
              <span className="font-semibold">{configSections[configSection].title}</span>
            </div>
            <pre className="whitespace-pre-wrap overflow-x-auto">
              {configSections[configSection].code}
            </pre>
          </div>
        </div>

        <div className="mb-8">
          <h3 className="text-xl font-semibold text-slate-700 mb-4">Directory Structure</h3>
          
          <div className="bg-slate-900 rounded-lg p-6 text-green-400 font-mono text-sm">
            <div className="flex items-center space-x-2 mb-4">
              <Database className="h-4 w-4" />
              <span className="font-semibold">Zero-Day Detector File Organization</span>
            </div>
            <pre className="whitespace-pre-wrap overflow-x-auto">
{`/etc/zdd/                          # Main configuration directory
├── config.yaml                    # Primary system configuration
├── logging.yaml                   # Logging configuration
├── network.yaml                   # Network monitoring settings
├── rules/                         # Detection rules directory
│   ├── network/                   # Network-based rules
│   ├── system/                    # System log rules
│   └── application/               # Application-specific rules
├── thresholds/                    # Statistical threshold definitions
│   ├── baselines.yaml
│   └── anomaly_detection.yaml
└── integrations/                  # External system integrations
    ├── siem.yaml
    ├── webhooks.yaml
    └── notifications.yaml

/var/lib/zdd/                      # Data and state directory
├── baselines/                     # Statistical baseline data
├── logs/                          # System logs
├── cache/                         # Runtime cache files
└── databases/                     # Local databases (GeoIP, etc.)

/usr/bin/zdd/                      # Binary installation
├── zdd-detector                   # Main detection daemon
├── zdd-config                     # Configuration utility
└── zdd-admin                      # Administration tool`}
            </pre>
          </div>
        </div>

        <div>
          <h3 className="text-xl font-semibold text-slate-700 mb-4">Configuration Management Tools</h3>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="bg-blue-50 rounded-lg p-4 border border-blue-200">
              <h4 className="font-semibold text-slate-700 mb-3">Configuration Validation</h4>
              <div className="bg-slate-800 rounded p-3 text-green-400 font-mono text-xs">
                <code># Validate configuration files<br/>
                zdd-config validate --all<br/>
                zdd-config test-rules --rule-id port_scan_001<br/>
                zdd-config check-syntax /etc/zdd/rules/</code>
              </div>
            </div>
            
            <div className="bg-green-50 rounded-lg p-4 border border-green-200">
              <h4 className="font-semibold text-slate-700 mb-3">Live Configuration Updates</h4>
              <div className="bg-slate-800 rounded p-3 text-green-400 font-mono text-xs">
                <code># Hot reload configuration<br/>
                zdd-admin reload-config<br/>
                zdd-admin enable-rule --rule-id network_ddos_001<br/>
                zdd-admin set-threshold --metric connections_per_min --value 50</code>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}