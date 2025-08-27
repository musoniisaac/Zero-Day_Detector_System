import React, { useState } from 'react';
import { Settings, Code, FileText, AlertTriangle } from 'lucide-react';

export function RuleEngine() {
  const [selectedRule, setSelectedRule] = useState<'port-scan' | 'brute-force' | 'ddos' | 'data-exfil'>('port-scan');

  const ruleExamples = {
    'port-scan': {
      name: 'Port Scan Detection',
      description: 'Detects rapid sequential connection attempts across multiple ports',
      code: `{
  "rule_id": "port_scan_001",
  "name": "Port Scan Detection",
  "category": "network",
  "severity": "medium",
  "conditions": {
    "source_ip_connections": {
      "threshold": 20,
      "time_window": "60s",
      "unique_ports": 10
    }
  },
  "action": "alert"
}`
    },
    'brute-force': {
      name: 'Brute Force Attack',
      description: 'Identifies repeated failed authentication attempts',
      code: `{
  "rule_id": "brute_force_001",
  "name": "SSH Brute Force",
  "category": "authentication",
  "severity": "high",
  "conditions": {
    "failed_logins": {
      "threshold": 5,
      "time_window": "300s",
      "same_source": true
    }
  },
  "action": "alert_and_block"
}`
    },
    'ddos': {
      name: 'DDoS Detection',
      description: 'Monitors for distributed denial of service patterns',
      code: `{
  "rule_id": "ddos_001",
  "name": "HTTP DDoS Detection",
  "category": "network",
  "severity": "critical",
  "conditions": {
    "request_rate": {
      "threshold": 1000,
      "time_window": "60s",
      "min_sources": 50
    }
  },
  "action": "immediate_alert"
}`
    },
    'data-exfil': {
      name: 'Data Exfiltration',
      description: 'Detects unusual outbound data transfer patterns',
      code: `{
  "rule_id": "data_exfil_001",
  "name": "Large Data Transfer",
  "category": "data_protection",
  "severity": "high",
  "conditions": {
    "outbound_bytes": {
      "threshold": 1073741824,
      "time_window": "3600s",
      "unusual_destination": true
    }
  },
  "action": "alert"
}`
    }
  };

  return (
    <div className="space-y-8">
      <div className="bg-white rounded-lg shadow-sm border border-slate-200 p-6">
        <h2 className="text-2xl font-bold text-slate-800 mb-6">Rule Engine Specification</h2>
        
        <div className="mb-6">
          <h3 className="text-xl font-semibold text-slate-700 mb-4">Engine Architecture</h3>
          <p className="text-slate-600 leading-relaxed mb-4">
            The rule engine operates on a multi-threaded architecture with parallel processing capabilities. 
            Each rule is compiled into an optimized detection pattern that can be applied to incoming data streams 
            with minimal computational overhead.
          </p>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <h4 className="font-semibold text-slate-700 mb-2">Rule Processing Flow</h4>
              <ol className="text-slate-600 space-y-1 text-sm">
                <li>1. Rule compilation and validation</li>
                <li>2. Pattern matching against data streams</li>
                <li>3. Condition evaluation and scoring</li>
                <li>4. Threshold comparison and decision making</li>
                <li>5. Action execution and alert generation</li>
              </ol>
            </div>
            
            <div>
              <h4 className="font-semibible text-slate-700 mb-2">Performance Optimizations</h4>
              <ul className="text-slate-600 space-y-1 text-sm">
                <li>• Compiled rule sets for faster execution</li>
                <li>• Memory-mapped rule storage</li>
                <li>• Parallel processing threads</li>
                <li>• Optimized pattern matching algorithms</li>
                <li>• Lazy evaluation for complex conditions</li>
              </ul>
            </div>
          </div>
        </div>
      </div>

      <div className="bg-white rounded-lg shadow-sm border border-slate-200 p-6">
        <h3 className="text-xl font-semibold text-slate-700 mb-4">Detection Rule Examples</h3>
        
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-4 mb-6">
          {Object.entries(ruleExamples).map(([key, rule]) => (
            <button
              key={key}
              onClick={() => setSelectedRule(key as any)}
              className={`p-3 rounded-lg text-left transition-colors ${
                selectedRule === key
                  ? 'bg-blue-100 border border-blue-300 text-blue-700'
                  : 'bg-slate-50 border border-slate-200 text-slate-700 hover:bg-slate-100'
              }`}
            >
              <div className="font-medium text-sm">{rule.name}</div>
              <div className="text-xs opacity-75 mt-1">{rule.description}</div>
            </button>
          ))}
        </div>

        <div className="bg-slate-900 rounded-lg p-6 text-green-400 font-mono text-sm">
          <div className="flex items-center space-x-2 mb-4">
            <Code className="h-4 w-4" />
            <span className="font-semibold">{ruleExamples[selectedRule].name} Configuration</span>
          </div>
          <pre className="whitespace-pre-wrap overflow-x-auto">
            {ruleExamples[selectedRule].code}
          </pre>
        </div>
      </div>

      <div className="bg-white rounded-lg shadow-sm border border-slate-200 p-6">
        <h3 className="text-xl font-semibold text-slate-700 mb-4">Rule Configuration Schema</h3>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <h4 className="font-semibold text-slate-700 mb-3">Required Fields</h4>
            <div className="space-y-3">
              <div className="border-l-4 border-blue-400 pl-4">
                <div className="font-medium text-slate-700">rule_id</div>
                <div className="text-slate-600 text-sm">Unique identifier for the rule</div>
              </div>
              <div className="border-l-4 border-blue-400 pl-4">
                <div className="font-medium text-slate-700">name</div>
                <div className="text-slate-600 text-sm">Human-readable rule description</div>
              </div>
              <div className="border-l-4 border-blue-400 pl-4">
                <div className="font-medium text-slate-700">category</div>
                <div className="text-slate-600 text-sm">Rule classification (network, system, application)</div>
              </div>
              <div className="border-l-4 border-blue-400 pl-4">
                <div className="font-medium text-slate-700">severity</div>
                <div className="text-slate-600 text-sm">Alert level: low, medium, high, critical</div>
              </div>
            </div>
          </div>
          
          <div>
            <h4 className="font-semibold text-slate-700 mb-3">Condition Types</h4>
            <div className="space-y-3">
              <div className="border-l-4 border-green-400 pl-4">
                <div className="font-medium text-slate-700">threshold</div>
                <div className="text-slate-600 text-sm">Numeric threshold for counting events</div>
              </div>
              <div className="border-l-4 border-green-400 pl-4">
                <div className="font-medium text-slate-700">time_window</div>
                <div className="text-slate-600 text-sm">Time period for event aggregation</div>
              </div>
              <div className="border-l-4 border-green-400 pl-4">
                <div className="font-medium text-slate-700">pattern_match</div>
                <div className="text-slate-600 text-sm">Regular expression for log pattern matching</div>
              </div>
              <div className="border-l-4 border-green-400 pl-4">
                <div className="font-medium text-slate-700">statistical_deviation</div>
                <div className="text-slate-600 text-sm">Standard deviation threshold for anomaly detection</div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="bg-white rounded-lg shadow-sm border border-slate-200 p-6">
        <h3 className="text-xl font-semibold text-slate-700 mb-4">Rule Engine Implementation</h3>
        
        <div className="bg-slate-900 rounded-lg p-6 text-green-400 font-mono text-sm">
          <div className="flex items-center space-x-2 mb-4">
            <FileText className="h-4 w-4" />
            <span className="font-semibold">Core Rule Engine Logic (Python)</span>
          </div>
          <pre className="whitespace-pre-wrap overflow-x-auto">
{`class RuleEngine:
    def __init__(self, rules_path: str):
        self.rules = self.load_rules(rules_path)
        self.compiled_rules = self.compile_rules()
        self.event_windows = defaultdict(deque)
    
    def evaluate_event(self, event: dict) -> List[Alert]:
        alerts = []
        current_time = time.time()
        
        for rule in self.compiled_rules:
            if self.matches_conditions(event, rule, current_time):
                alert = self.create_alert(event, rule)
                alerts.append(alert)
        
        return alerts
    
    def matches_conditions(self, event: dict, rule: dict, timestamp: float) -> bool:
        for condition_name, condition in rule['conditions'].items():
            if not self.evaluate_condition(event, condition, timestamp):
                return False
        return True
    
    def evaluate_condition(self, event: dict, condition: dict, timestamp: float) -> bool:
        if 'threshold' in condition:
            return self.check_threshold(event, condition, timestamp)
        elif 'pattern_match' in condition:
            return self.check_pattern(event, condition)
        elif 'statistical_deviation' in condition:
            return self.check_statistical_anomaly(event, condition, timestamp)
        return False`}
          </pre>
        </div>
      </div>
    </div>
  );
}