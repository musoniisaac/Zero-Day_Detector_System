import React from 'react';
import { Monitor, Activity, Database, Network } from 'lucide-react';

export function Performance() {
  return (
    <div className="space-y-8">
      <div className="bg-white rounded-lg shadow-sm border border-slate-200 p-6">
        <h2 className="text-2xl font-bold text-slate-800 mb-6">Performance Benchmarks</h2>
        
        <div className="mb-8">
          <h3 className="text-xl font-semibold text-slate-700 mb-4">System Resource Requirements</h3>
          
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            <div className="bg-blue-50 rounded-lg p-4 border border-blue-200">
              <div className="flex items-center space-x-3 mb-3">
                <Monitor className="h-6 w-6 text-blue-600" />
                <h4 className="font-semibold text-blue-700">CPU Usage</h4>
              </div>
              <div className="text-2xl font-bold text-blue-600 mb-1">&lt; 5%</div>
              <p className="text-blue-600 text-sm">Average CPU utilization under normal load</p>
            </div>
            
            <div className="bg-green-50 rounded-lg p-4 border border-green-200">
              <div className="flex items-center space-x-3 mb-3">
                <Database className="h-6 w-6 text-green-600" />
                <h4 className="font-semibold text-green-700">Memory</h4>
              </div>
              <div className="text-2xl font-bold text-green-600 mb-1">&lt; 512MB</div>
              <p className="text-green-600 text-sm">Maximum RAM consumption including caches</p>
            </div>
            
            <div className="bg-orange-50 rounded-lg p-4 border border-orange-200">
              <div className="flex items-center space-x-3 mb-3">
                <Activity className="h-6 w-6 text-orange-600" />
                <h4 className="font-semibold text-orange-700">Latency</h4>
              </div>
              <div className="text-2xl font-bold text-orange-600 mb-1">&lt; 1s</div>
              <p className="text-orange-600 text-sm">Alert generation response time</p>
            </div>
            
            <div className="bg-purple-50 rounded-lg p-4 border border-purple-200">
              <div className="flex items-center space-x-3 mb-3">
                <Network className="h-6 w-6 text-purple-600" />
                <h4 className="font-semibold text-purple-700">Throughput</h4>
              </div>
              <div className="text-2xl font-bold text-purple-600 mb-1">10K+/s</div>
              <p className="text-purple-600 text-sm">Log events processed per second</p>
            </div>
          </div>
        </div>

        <div className="mb-8">
          <h3 className="text-xl font-semibold text-slate-700 mb-4">Benchmark Test Results</h3>
          
          <div className="overflow-x-auto">
            <table className="w-full border border-slate-200 rounded-lg">
              <thead className="bg-slate-50">
                <tr>
                  <th className="px-4 py-3 text-left font-semibold text-slate-700 border-b border-slate-200">Test Scenario</th>
                  <th className="px-4 py-3 text-left font-semibold text-slate-700 border-b border-slate-200">Events/Second</th>
                  <th className="px-4 py-3 text-left font-semibold text-slate-700 border-b border-slate-200">CPU Usage</th>
                  <th className="px-4 py-3 text-left font-semibold text-slate-700 border-b border-slate-200">Memory Usage</th>
                  <th className="px-4 py-3 text-left font-semibold text-slate-700 border-b border-slate-200">Detection Latency</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td className="px-4 py-3 text-slate-700 border-b border-slate-200">Normal Load</td>
                  <td className="px-4 py-3 text-slate-600 border-b border-slate-200">5,000</td>
                  <td className="px-4 py-3 text-slate-600 border-b border-slate-200">2.1%</td>
                  <td className="px-4 py-3 text-slate-600 border-b border-slate-200">245MB</td>
                  <td className="px-4 py-3 text-slate-600 border-b border-slate-200">0.3s</td>
                </tr>
                <tr>
                  <td className="px-4 py-3 text-slate-700 border-b border-slate-200">High Load</td>
                  <td className="px-4 py-3 text-slate-600 border-b border-slate-200">15,000</td>
                  <td className="px-4 py-3 text-slate-600 border-b border-slate-200">4.7%</td>
                  <td className="px-4 py-3 text-slate-600 border-b border-slate-200">398MB</td>
                  <td className="px-4 py-3 text-slate-600 border-b border-slate-200">0.8s</td>
                </tr>
                <tr>
                  <td className="px-4 py-3 text-slate-700 border-b border-slate-200">Attack Simulation</td>
                  <td className="px-4 py-3 text-slate-600 border-b border-slate-200">25,000</td>
                  <td className="px-4 py-3 text-slate-600 border-b border-slate-200">4.9%</td>
                  <td className="px-4 py-3 text-slate-600 border-b border-slate-200">467MB</td>
                  <td className="px-4 py-3 text-slate-600 border-b border-slate-200">0.9s</td>
                </tr>
                <tr>
                  <td className="px-4 py-3 text-slate-700">Stress Test (Peak)</td>
                  <td className="px-4 py-3 text-slate-600">50,000</td>
                  <td className="px-4 py-3 text-slate-600">8.2%</td>
                  <td className="px-4 py-3 text-slate-600">511MB</td>
                  <td className="px-4 py-3 text-slate-600">1.2s</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        <div className="mb-8">
          <h3 className="text-xl font-semibold text-slate-700 mb-4">Scalability Guidelines</h3>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <h4 className="font-semibold text-slate-700 mb-3">Horizontal Scaling</h4>
              <div className="bg-slate-50 rounded p-4 border border-slate-200">
                <ul className="text-slate-600 space-y-2 text-sm">
                  <li>• <strong>Multi-node deployment:</strong> Distribute across network segments</li>
                  <li>• <strong>Load balancing:</strong> Round-robin log distribution</li>
                  <li>• <strong>Centralized management:</strong> Unified configuration and alerting</li>
                  <li>• <strong>Data aggregation:</strong> Collect alerts from multiple sensors</li>
                </ul>
              </div>
            </div>
            
            <div>
              <h4 className="font-semibold text-slate-700 mb-3">Vertical Scaling</h4>
              <div className="bg-slate-50 rounded p-4 border border-slate-200">
                <ul className="text-slate-600 space-y-2 text-sm">
                  <li>• <strong>CPU cores:</strong> Linear scaling up to 8 cores</li>
                  <li>• <strong>Memory allocation:</strong> Configurable cache sizes</li>
                  <li>• <strong>Storage optimization:</strong> SSD recommended for high IOPS</li>
                  <li>• <strong>Network bandwidth:</strong> Minimum 1Gbps for large deployments</li>
                </ul>
              </div>
            </div>
          </div>
        </div>

        <div>
          <h3 className="text-xl font-semibold text-slate-700 mb-4">Performance Monitoring</h3>
          
          <div className="bg-slate-900 rounded-lg p-6 text-green-400 font-mono text-sm">
            <div className="flex items-center space-x-2 mb-4">
              <Activity className="h-4 w-4" />
              <span className="font-semibold">Performance Metrics Collection</span>
            </div>
            <pre className="whitespace-pre-wrap overflow-x-auto">
{`# Performance monitoring configuration
metrics:
  collection_interval: 10s      # How often to collect metrics
  
  system_metrics:
    - cpu_usage_percent
    - memory_usage_mb  
    - disk_io_ops_per_sec
    - network_bytes_per_sec
    
  application_metrics:
    - events_processed_per_sec
    - rules_evaluated_per_sec
    - alerts_generated_per_min
    - detection_latency_ms
    - queue_depth
    
  thresholds:
    cpu_usage_percent: 5.0
    memory_usage_mb: 512
    detection_latency_ms: 1000
    queue_depth: 1000

# Performance alerting
performance_alerts:
  cpu_threshold_exceeded:
    severity: warning
    action: notify_admin
    
  memory_threshold_exceeded:
    severity: critical
    action: [notify_admin, reduce_cache_size]
    
  detection_latency_high:
    severity: warning  
    action: [notify_admin, increase_worker_threads]`}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
}