import React from 'react';
import { AlertTriangle, Mail, Phone, Slack, Webhook } from 'lucide-react';

export function AlertSystem() {
  return (
    <div className="space-y-8">
      <div className="bg-white rounded-lg shadow-sm border border-slate-200 p-6">
        <h2 className="text-2xl font-bold text-slate-800 mb-6">Alert System Design</h2>
        
        <div className="mb-8">
          <h3 className="text-xl font-semibold text-slate-700 mb-4">Severity Classification</h3>
          
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="bg-green-50 border border-green-200 rounded-lg p-4">
              <div className="flex items-center space-x-2 mb-2">
                <div className="w-3 h-3 bg-green-500 rounded-full"></div>
                <h4 className="font-semibold text-green-700">Low</h4>
              </div>
              <p className="text-green-600 text-sm mb-3">Informational events requiring monitoring</p>
              <ul className="text-green-600 text-xs space-y-1">
                <li>• Minor threshold breaches</li>
                <li>• Configuration changes</li>
                <li>• System maintenance events</li>
              </ul>
            </div>
            
            <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
              <div className="flex items-center space-x-2 mb-2">
                <div className="w-3 h-3 bg-yellow-500 rounded-full"></div>
                <h4 className="font-semibold text-yellow-700">Medium</h4>
              </div>
              <p className="text-yellow-600 text-sm mb-3">Suspicious activity requiring investigation</p>
              <ul className="text-yellow-600 text-xs space-y-1">
                <li>• Port scanning attempts</li>
                <li>• Unusual user behavior</li>
                <li>• Failed authentication spikes</li>
              </ul>
            </div>
            
            <div className="bg-orange-50 border border-orange-200 rounded-lg p-4">
              <div className="flex items-center space-x-2 mb-2">
                <div className="w-3 h-3 bg-orange-500 rounded-full"></div>
                <h4 className="font-semibold text-orange-700">High</h4>
              </div>
              <p className="text-orange-600 text-sm mb-3">Confirmed threats requiring immediate action</p>
              <ul className="text-orange-600 text-xs space-y-1">
                <li>• Successful intrusions</li>
                <li>• Data exfiltration attempts</li>
                <li>• Privilege escalation</li>
              </ul>
            </div>
            
            <div className="bg-red-50 border border-red-200 rounded-lg p-4">
              <div className="flex items-center space-x-2 mb-2">
                <div className="w-3 h-3 bg-red-500 rounded-full"></div>
                <h4 className="font-semibold text-red-700">Critical</h4>
              </div>
              <p className="text-red-600 text-sm mb-3">Active attacks requiring emergency response</p>
              <ul className="text-red-600 text-xs space-y-1">
                <li>• Active data breaches</li>
                <li>• System compromises</li>
                <li>• DDoS attacks</li>
              </ul>
            </div>
          </div>
        </div>

        <div className="mb-8">
          <h3 className="text-xl font-semibold text-slate-700 mb-4">Notification Channels</h3>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <h4 className="font-semibold text-slate-700 mb-3">Primary Channels</h4>
              <div className="space-y-3">
                <div className="flex items-center space-x-3 p-3 bg-slate-50 rounded border border-slate-200">
                  <Mail className="h-5 w-5 text-blue-600" />
                  <div>
                    <div className="font-medium text-slate-700">Email Notifications</div>
                    <div className="text-slate-600 text-sm">SMTP with HTML templates and severity-based routing</div>
                  </div>
                </div>
                
                <div className="flex items-center space-x-3 p-3 bg-slate-50 rounded border border-slate-200">
                  <Phone className="h-5 w-5 text-green-600" />
                  <div>
                    <div className="font-medium text-slate-700">SMS Alerts</div>
                    <div className="text-slate-600 text-sm">Critical alerts via SMS gateway integration</div>
                  </div>
                </div>
                
                <div className="flex items-center space-x-3 p-3 bg-slate-50 rounded border border-slate-200">
                  <Slack className="h-5 w-5 text-purple-600" />
                  <div>
                    <div className="font-medium text-slate-700">Slack Integration</div>
                    <div className="text-slate-600 text-sm">Real-time alerts to security team channels</div>
                  </div>
                </div>
              </div>
            </div>
            
            <div>
              <h4 className="font-semibold text-slate-700 mb-3">Integration Channels</h4>
              <div className="space-y-3">
                <div className="flex items-center space-x-3 p-3 bg-slate-50 rounded border border-slate-200">
                  <Webhook className="h-5 w-5 text-orange-600" />
                  <div>
                    <div className="font-medium text-slate-700">Webhook Endpoints</div>
                    <div className="text-slate-600 text-sm">JSON payloads to external security platforms</div>
                  </div>
                </div>
                
                <div className="flex items-center space-x-3 p-3 bg-slate-50 rounded border border-slate-200">
                  <AlertTriangle className="h-5 w-5 text-red-600" />
                  <div>
                    <div className="font-medium text-slate-700">SIEM Integration</div>
                    <div className="text-slate-600 text-sm">Syslog forwarding to SIEM platforms</div>
                  </div>
                </div>
                
                <div className="flex items-center space-x-3 p-3 bg-slate-50 rounded border border-slate-200">
                  <Mail className="h-5 w-5 text-indigo-600" />
                  <div>
                    <div className="font-medium text-slate-700">API Endpoints</div>
                    <div className="text-slate-600 text-sm">RESTful API for custom integrations</div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="mb-8">
          <h3 className="text-xl font-semibold text-slate-700 mb-4">Alert Escalation Matrix</h3>
          
          <div className="overflow-x-auto">
            <table className="w-full border border-slate-200 rounded-lg">
              <thead className="bg-slate-50">
                <tr>
                  <th className="px-4 py-3 text-left font-semibold text-slate-700 border-b border-slate-200">Severity</th>
                  <th className="px-4 py-3 text-left font-semibold text-slate-700 border-b border-slate-200">Response Time</th>
                  <th className="px-4 py-3 text-left font-semibold text-slate-700 border-b border-slate-200">Notification Method</th>
                  <th className="px-4 py-3 text-left font-semibold text-slate-700 border-b border-slate-200">Escalation Path</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td className="px-4 py-3 border-b border-slate-200">
                    <span className="px-2 py-1 bg-green-100 text-green-700 rounded text-xs font-medium">Low</span>
                  </td>
                  <td className="px-4 py-3 text-slate-600 border-b border-slate-200 text-sm">Within 15 minutes</td>
                  <td className="px-4 py-3 text-slate-600 border-b border-slate-200 text-sm">Email to security team</td>
                  <td className="px-4 py-3 text-slate-600 border-b border-slate-200 text-sm">Daily review</td>
                </tr>
                <tr>
                  <td className="px-4 py-3 border-b border-slate-200">
                    <span className="px-2 py-1 bg-yellow-100 text-yellow-700 rounded text-xs font-medium">Medium</span>
                  </td>
                  <td className="px-4 py-3 text-slate-600 border-b border-slate-200 text-sm">Within 5 minutes</td>
                  <td className="px-4 py-3 text-slate-600 border-b border-slate-200 text-sm">Email + Slack notification</td>
                  <td className="px-4 py-3 text-slate-600 border-b border-slate-200 text-sm">4-hour review</td>
                </tr>
                <tr>
                  <td className="px-4 py-3 border-b border-slate-200">
                    <span className="px-2 py-1 bg-orange-100 text-orange-700 rounded text-xs font-medium">High</span>
                  </td>
                  <td className="px-4 py-3 text-slate-600 border-b border-slate-200 text-sm">Within 2 minutes</td>
                  <td className="px-4 py-3 text-slate-600 border-b border-slate-200 text-sm">All channels + phone call</td>
                  <td className="px-4 py-3 text-slate-600 border-b border-slate-200 text-sm">Immediate response</td>
                </tr>
                <tr>
                  <td className="px-4 py-3">
                    <span className="px-2 py-1 bg-red-100 text-red-700 rounded text-xs font-medium">Critical</span>
                  </td>
                  <td className="px-4 py-3 text-slate-600 text-sm">Immediate (&lt;30 seconds)</td>
                  <td className="px-4 py-3 text-slate-600 text-sm">All channels + emergency contact</td>
                  <td className="px-4 py-3 text-slate-600 text-sm">Emergency protocols</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        <div>
          <h3 className="text-xl font-semibold text-slate-700 mb-4">Alert Payload Structure</h3>
          
          <div className="bg-slate-900 rounded-lg p-6 text-green-400 font-mono text-sm">
            <div className="flex items-center space-x-2 mb-4">
              <AlertTriangle className="h-4 w-4" />
              <span className="font-semibold">Alert JSON Schema</span>
            </div>
            <pre className="whitespace-pre-wrap overflow-x-auto">
{`{
  "alert_id": "alert_20250102_143022_001",
  "timestamp": "2025-01-02T14:30:22.123Z",
  "severity": "high",
  "rule_id": "port_scan_001",
  "rule_name": "Port Scan Detection",
  "source": {
    "ip_address": "192.168.1.100",
    "hostname": "workstation-01",
    "user": "jdoe"
  },
  "detection_details": {
    "metric": "port_connections",
    "current_value": 45,
    "threshold": 20,
    "baseline": 8.2,
    "z_score": 4.8,
    "confidence": 0.95
  },
  "evidence": {
    "log_entries": [...],
    "network_flows": [...],
    "related_events": [...]
  },
  "recommended_actions": [
    "Block source IP address",
    "Investigate user account activity",
    "Review firewall logs"
  ]
}`}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
}