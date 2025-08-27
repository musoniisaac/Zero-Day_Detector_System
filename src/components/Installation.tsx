import React, { useState } from 'react';
import { Server, Download, Settings, CheckCircle } from 'lucide-react';

export function Installation() {
  const [installType, setInstallType] = useState<'linux' | 'windows' | 'docker'>('linux');

  const installationGuides = {
    linux: {
      title: 'Linux Installation',
      steps: [
        'Download and extract the Zero-Day Detector package',
        'Install system dependencies',
        'Configure system user and permissions',
        'Initialize configuration files',
        'Start the detection service',
        'Verify installation and test detection'
      ],
      code: `# Linux Installation Script
#!/bin/bash

# Download Zero-Day Detector
wget https://releases.zdd.security/v2.1.0/zdd-linux-amd64.tar.gz
tar -xzf zdd-linux-amd64.tar.gz

# Install dependencies
sudo apt update
sudo apt install -y libpcap-dev python3-dev build-essential

# Create system user
sudo useradd -r -s /bin/false zdd-detector
sudo usermod -a -G zdd-detector $USER

# Install binaries
sudo cp bin/* /usr/local/bin/
sudo chmod +x /usr/local/bin/zdd-*

# Create directories
sudo mkdir -p /etc/zdd/{rules,thresholds,integrations}
sudo mkdir -p /var/lib/zdd/{baselines,logs,cache,databases}
sudo mkdir -p /var/log/zdd

# Set permissions
sudo chown -R zdd-detector:zdd-detector /etc/zdd /var/lib/zdd /var/log/zdd
sudo chmod 755 /etc/zdd /var/lib/zdd
sudo chmod 644 /etc/zdd/*.yaml

# Install default configuration
sudo cp config/default/* /etc/zdd/
sudo cp rules/default/* /etc/zdd/rules/

# Create systemd service
sudo cp systemd/zdd-detector.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable zdd-detector

# Start service
sudo systemctl start zdd-detector

# Verify installation
sudo systemctl status zdd-detector
zdd-config validate --all`
    },
    windows: {
      title: 'Windows Installation',
      steps: [
        'Download Windows installer package',
        'Run installer with administrator privileges',
        'Configure Windows service settings',
        'Set up log file monitoring permissions',
        'Initialize detection rules',
        'Start Zero-Day Detector service'
      ],
      code: `# Windows PowerShell Installation
# Run as Administrator

# Download installer
$url = "https://releases.zdd.security/v2.1.0/zdd-windows-amd64.msi"
$output = "$env:TEMP\\zdd-installer.msi"
Invoke-WebRequest -Uri $url -OutFile $output

# Install with default settings
Start-Process msiexec.exe -Wait -ArgumentList '/i', $output, '/quiet', '/norestart'

# Configure service account
$serviceName = "ZDDDetector"
$serviceAccount = "NT SERVICE\\\\ZDDDetector"

# Grant log access permissions
icacls "C:\\\\Windows\\\\System32\\\\LogFiles" /grant "\${serviceAccount}:(R)" /T
icacls "C:\\\\inetpub\\\\logs" /grant "\${serviceAccount}:(R)" /T

# Start service
Start-Service -Name $serviceName

# Verify installation
Get-Service -Name $serviceName
& "C:\\Program Files\\ZDD\\zdd-config.exe" validate --all

# Configure Windows Firewall (if needed)
New-NetFirewallRule -DisplayName "ZDD Detector" -Direction Inbound -Protocol TCP -LocalPort 8080 -Action Allow`
    },
    docker: {
      title: 'Docker Deployment',
      steps: [
        'Pull the official Zero-Day Detector Docker image',
        'Create configuration volume mounts',
        'Set up environment variables',
        'Configure network access for monitoring',
        'Deploy container with proper security context',
        'Verify container health and connectivity'
      ],
      code: `# Docker Deployment Guide

# Pull official image
docker pull zdd.security/detector:v2.1.0

# Create configuration directory
mkdir -p ./zdd-config/{rules,thresholds,integrations}
mkdir -p ./zdd-data/{baselines,logs,cache}

# Download default configuration
curl -L https://releases.zdd.security/v2.1.0/config-docker.tar.gz | tar -xz -C ./zdd-config/

# Create Docker Compose file
cat > docker-compose.yml << EOF
version: '3.8'
services:
  zdd-detector:
    image: zdd.security/detector:v2.1.0
    container_name: zdd-detector
    restart: unless-stopped
    
    # Network monitoring requires host network access
    network_mode: host
    
    # Security context
    cap_add:
      - NET_RAW
      - NET_ADMIN
    
    volumes:
      - ./zdd-config:/etc/zdd:ro
      - ./zdd-data:/var/lib/zdd
      - /var/log:/host/var/log:ro
      
    environment:
      - ZDD_LOG_LEVEL=INFO
      - ZDD_WORKER_THREADS=4
      
    healthcheck:
      test: ["CMD", "zdd-config", "health-check"]
      interval: 30s
      timeout: 10s
      retries: 3
EOF

# Deploy
docker-compose up -d

# Verify deployment
docker-compose logs -f zdd-detector`
    }
  };

  return (
    <div className="space-y-8">
      <div className="bg-white rounded-lg shadow-sm border border-slate-200 p-6">
        <h2 className="text-2xl font-bold text-slate-800 mb-6">Installation & Deployment</h2>
        
        <div className="mb-6">
          <h3 className="text-xl font-semibold text-slate-700 mb-4">Platform Selection</h3>
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
            {Object.entries(installationGuides).map(([key, guide]) => (
              <button
                key={key}
                onClick={() => setInstallType(key as any)}
                className={`p-4 rounded-lg text-left transition-colors ${
                  installType === key
                    ? 'bg-blue-100 border border-blue-300 text-blue-700'
                    : 'bg-slate-50 border border-slate-200 text-slate-700 hover:bg-slate-100'
                }`}
              >
                <div className="flex items-center space-x-3 mb-2">
                  <Server className="h-5 w-5" />
                  <div className="font-medium">{guide.title}</div>
                </div>
                <div className="text-sm opacity-75">
                  {key === 'linux' && 'Ubuntu, CentOS, RHEL support'}
                  {key === 'windows' && 'Windows Server 2016+ and Windows 10+'}
                  {key === 'docker' && 'Containerized deployment with Docker'}
                </div>
              </button>
            ))}
          </div>
        </div>

        <div className="mb-8">
          <h3 className="text-xl font-semibold text-slate-700 mb-4">Installation Steps</h3>
          
          <div className="mb-6">
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {installationGuides[installType].steps.map((step, index) => (
                <div key={index} className="flex items-start space-x-3 p-3 bg-slate-50 rounded border border-slate-200">
                  <div className="flex-shrink-0 w-6 h-6 bg-blue-100 text-blue-700 rounded-full flex items-center justify-center text-sm font-semibold">
                    {index + 1}
                  </div>
                  <div className="text-slate-700 text-sm">{step}</div>
                </div>
              ))}
            </div>
          </div>

          <div className="bg-slate-900 rounded-lg p-6 text-green-400 font-mono text-sm">
            <div className="flex items-center space-x-2 mb-4">
              <Download className="h-4 w-4" />
              <span className="font-semibold">{installationGuides[installType].title} Commands</span>
            </div>
            <pre className="whitespace-pre-wrap overflow-x-auto">
              {installationGuides[installType].code}
            </pre>
          </div>
        </div>

        <div className="mb-8">
          <h3 className="text-xl font-semibold text-slate-700 mb-4">Post-Installation Verification</h3>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <h4 className="font-semibold text-slate-700 mb-3">System Health Checks</h4>
              <div className="space-y-3">
                <div className="flex items-center space-x-2 p-2 bg-green-50 rounded border border-green-200">
                  <CheckCircle className="h-4 w-4 text-green-600" />
                  <span className="text-green-700 text-sm">Service status verification</span>
                </div>
                <div className="flex items-center space-x-2 p-2 bg-green-50 rounded border border-green-200">
                  <CheckCircle className="h-4 w-4 text-green-600" />
                  <span className="text-green-700 text-sm">Configuration validation</span>
                </div>
                <div className="flex items-center space-x-2 p-2 bg-green-50 rounded border border-green-200">
                  <CheckCircle className="h-4 w-4 text-green-600" />
                  <span className="text-green-700 text-sm">Network interface binding</span>
                </div>
                <div className="flex items-center space-x-2 p-2 bg-green-50 rounded border border-green-200">
                  <CheckCircle className="h-4 w-4 text-green-600" />
                  <span className="text-green-700 text-sm">Log file access permissions</span>
                </div>
              </div>
            </div>
            
            <div>
              <h4 className="font-semibold text-slate-700 mb-3">Functional Tests</h4>
              <div className="bg-slate-50 rounded p-4 border border-slate-200">
                <ul className="text-slate-600 space-y-2 text-sm">
                  <li>• <strong>Rule loading:</strong> Verify all rules compile successfully</li>
                  <li>• <strong>Alert generation:</strong> Test with simulated events</li>
                  <li>• <strong>Notification delivery:</strong> Confirm all channels work</li>
                  <li>• <strong>Performance baseline:</strong> Monitor resource usage</li>
                  <li>• <strong>Data collection:</strong> Verify log and network capture</li>
                </ul>
              </div>
            </div>
          </div>
        </div>

        <div>
          <h3 className="text-xl font-semibold text-slate-700 mb-4">System Requirements</h3>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <h4 className="font-semibold text-slate-700 mb-3">Minimum Requirements</h4>
              <div className="bg-slate-50 rounded p-4 border border-slate-200">
                <ul className="text-slate-600 space-y-1 text-sm">
                  <li>• CPU: 2 cores, 2.0 GHz</li>
                  <li>• RAM: 4GB (1GB available for ZDD)</li>
                  <li>• Storage: 20GB available space</li>
                  <li>• Network: 100Mbps connection</li>
                  <li>• OS: Linux 4.0+ or Windows Server 2016+</li>
                </ul>
              </div>
            </div>
            
            <div>
              <h4 className="font-semibold text-slate-700 mb-3">Recommended Requirements</h4>
              <div className="bg-blue-50 rounded p-4 border border-blue-200">
                <ul className="text-blue-700 space-y-1 text-sm">
                  <li>• CPU: 4+ cores, 3.0+ GHz</li>
                  <li>• RAM: 8GB (2GB available for ZDD)</li>
                  <li>• Storage: 100GB SSD</li>
                  <li>• Network: 1Gbps connection</li>
                  <li>• OS: Ubuntu 20.04+ or Windows Server 2019+</li>
                </ul>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}