import React, { useState } from 'react';
import { Shield, Network, Activity, FileText, Settings, AlertTriangle, Code, Server, Database, Monitor } from 'lucide-react';
import { Navigation } from './components/Navigation';
import { SystemArchitecture } from './components/SystemArchitecture';
import { RuleEngine } from './components/RuleEngine';
import { StatisticalAnalysis } from './components/StatisticalAnalysis';
import { AlertSystem } from './components/AlertSystem';
import { Configuration } from './components/Configuration';
import { Performance } from './components/Performance';
import { Installation } from './components/Installation';
import { CodeSamples } from './components/CodeSamples';

type Section = 'overview' | 'architecture' | 'rules' | 'statistics' | 'alerts' | 'config' | 'performance' | 'installation' | 'code';

function App() {
  const [activeSection, setActiveSection] = useState<Section>('overview');

  const sections = [
    { id: 'overview' as Section, title: 'System Overview', icon: Shield },
    { id: 'architecture' as Section, title: 'Architecture', icon: Network },
    { id: 'rules' as Section, title: 'Rule Engine', icon: Settings },
    { id: 'statistics' as Section, title: 'Statistical Analysis', icon: Activity },
    { id: 'alerts' as Section, title: 'Alert System', icon: AlertTriangle },
    { id: 'config' as Section, title: 'Configuration', icon: FileText },
    { id: 'performance' as Section, title: 'Performance', icon: Monitor },
    { id: 'installation' as Section, title: 'Installation', icon: Server },
    { id: 'code' as Section, title: 'Code Samples', icon: Code },
  ];

  const renderSection = () => {
    switch (activeSection) {
      case 'overview':
        return <SystemOverview />;
      case 'architecture':
        return <SystemArchitecture />;
      case 'rules':
        return <RuleEngine />;
      case 'statistics':
        return <StatisticalAnalysis />;
      case 'alerts':
        return <AlertSystem />;
      case 'config':
        return <Configuration />;
      case 'performance':
        return <Performance />;
      case 'installation':
        return <Installation />;
      case 'code':
        return <CodeSamples />;
      default:
        return <SystemOverview />;
    }
  };

  return (
    <div className="min-h-screen bg-slate-50">
      <header className="bg-blue-900 text-white shadow-lg">
        <div className="max-w-7xl mx-auto px-6 py-4">
          <div className="flex items-center space-x-3">
            <Shield className="h-8 w-8" />
            <div>
              <h1 className="text-2xl font-bold">Zero-Day Detector System</h1>
              <p className="text-blue-200 text-sm">Lightweight Real-Time Security Monitoring Solution</p>
            </div>
          </div>
        </div>
      </header>

      <div className="max-w-7xl mx-auto px-6 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
          <div className="lg:col-span-1">
            <Navigation 
              sections={sections}
              activeSection={activeSection}
              onSectionChange={setActiveSection}
            />
          </div>
          
          <div className="lg:col-span-3">
            {renderSection()}
          </div>
        </div>
      </div>
    </div>
  );
}

function SystemOverview() {
  return (
    <div className="space-y-8">
      <div className="bg-white rounded-lg shadow-sm border border-slate-200 p-6">
        <h2 className="text-2xl font-bold text-slate-800 mb-4">Executive Summary</h2>
        <p className="text-slate-600 leading-relaxed mb-6">
          The Zero-Day Detector System is a lightweight, real-time security monitoring solution designed to identify 
          and alert on potential zero-day attacks and advanced persistent threats. Unlike traditional signature-based 
          systems, it employs behavioral analysis and statistical anomaly detection to identify previously unknown threats.
        </p>
        
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          <div className="bg-blue-50 rounded-lg p-4 border border-blue-200">
            <div className="flex items-center space-x-3 mb-3">
              <Activity className="h-6 w-6 text-blue-600" />
              <h3 className="font-semibold text-slate-800">Real-Time Monitoring</h3>
            </div>
            <p className="text-slate-600 text-sm">
              Continuous analysis of system logs and network traffic with sub-second response times.
            </p>
          </div>
          
          <div className="bg-green-50 rounded-lg p-4 border border-green-200">
            <div className="flex items-center space-x-3 mb-3">
              <Database className="h-6 w-6 text-green-600" />
              <h3 className="font-semibold text-slate-800">Resource Efficient</h3>
            </div>
            <p className="text-slate-600 text-sm">
              Operates with minimal system impact: &lt;5% CPU usage and &lt;512MB RAM consumption.
            </p>
          </div>
          
          <div className="bg-orange-50 rounded-lg p-4 border border-orange-200">
            <div className="flex items-center space-x-3 mb-3">
              <Settings className="h-6 w-6 text-orange-600" />
              <h3 className="font-semibold text-slate-800">Highly Configurable</h3>
            </div>
            <p className="text-slate-600 text-sm">
              Flexible rule engine with customizable thresholds and detection patterns.
            </p>
          </div>
        </div>
      </div>

      <div className="bg-white rounded-lg shadow-sm border border-slate-200 p-6">
        <h2 className="text-xl font-bold text-slate-800 mb-4">Key Requirements</h2>
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <h3 className="font-semibold text-slate-700 mb-2">Performance Targets</h3>
              <ul className="text-slate-600 space-y-1 text-sm">
                <li>• CPU Usage: &lt; 5% under normal load</li>
                <li>• Memory Usage: &lt; 512MB RAM</li>
                <li>• Detection Latency: &lt; 1 second</li>
                <li>• Log Processing: 10,000+ events/second</li>
              </ul>
            </div>
            
            <div>
              <h3 className="font-semibold text-slate-700 mb-2">Compatibility</h3>
              <ul className="text-slate-600 space-y-1 text-sm">
                <li>• Linux (Ubuntu 18.04+, CentOS 7+)</li>
                <li>• Windows (Server 2016+, Windows 10+)</li>
                <li>• Network protocols: HTTP/HTTPS, DNS, TCP/UDP</li>
                <li>• Log formats: Syslog, Apache, IIS, CEF</li>
              </ul>
            </div>
          </div>
        </div>
      </div>

      <div className="bg-white rounded-lg shadow-sm border border-slate-200 p-6">
        <h2 className="text-xl font-bold text-slate-800 mb-4">Detection Capabilities</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <h3 className="font-semibold text-slate-700 mb-3">Network Anomalies</h3>
            <div className="space-y-2 text-sm">
              <div className="flex items-center space-x-2">
                <div className="w-2 h-2 bg-red-400 rounded-full"></div>
                <span className="text-slate-600">Port scanning detection</span>
              </div>
              <div className="flex items-center space-x-2">
                <div className="w-2 h-2 bg-red-400 rounded-full"></div>
                <span className="text-slate-600">DDoS attack identification</span>
              </div>
              <div className="flex items-center space-x-2">
                <div className="w-2 h-2 bg-red-400 rounded-full"></div>
                <span className="text-slate-600">Unusual outbound connections</span>
              </div>
              <div className="flex items-center space-x-2">
                <div className="w-2 h-2 bg-red-400 rounded-full"></div>
                <span className="text-slate-600">Traffic volume anomalies</span>
              </div>
            </div>
          </div>
          
          <div>
            <h3 className="font-semibold text-slate-700 mb-3">System Behavior</h3>
            <div className="space-y-2 text-sm">
              <div className="flex items-center space-x-2">
                <div className="w-2 h-2 bg-orange-400 rounded-full"></div>
                <span className="text-slate-600">Authentication anomalies</span>
              </div>
              <div className="flex items-center space-x-2">
                <div className="w-2 h-2 bg-orange-400 rounded-full"></div>
                <span className="text-slate-600">Process execution patterns</span>
              </div>
              <div className="flex items-center space-x-2">
                <div className="w-2 h-2 bg-orange-400 rounded-full"></div>
                <span className="text-slate-600">File system access violations</span>
              </div>
              <div className="flex items-center space-x-2">
                <div className="w-2 h-2 bg-orange-400 rounded-full"></div>
                <span className="text-slate-600">Privilege escalation attempts</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default App;