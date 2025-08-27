import React from 'react';
import { Activity, BarChart, TrendingUp, Calculator } from 'lucide-react';

export function StatisticalAnalysis() {
  return (
    <div className="space-y-8">
      <div className="bg-white rounded-lg shadow-sm border border-slate-200 p-6">
        <h2 className="text-2xl font-bold text-slate-800 mb-6">Statistical Threshold Analysis</h2>
        
        <div className="mb-8">
          <h3 className="text-xl font-semibold text-slate-700 mb-4">Sliding Window Algorithm</h3>
          <p className="text-slate-600 leading-relaxed mb-4">
            The system employs a sliding window approach to establish dynamic baselines for various metrics. 
            This allows for adaptive threshold calculation that accounts for normal operational variations 
            while maintaining sensitivity to anomalous behavior.
          </p>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="bg-blue-50 rounded-lg p-4 border border-blue-200">
              <div className="flex items-center space-x-3 mb-3">
                <BarChart className="h-6 w-6 text-blue-600" />
                <h4 className="font-semibold">Window Configuration</h4>
              </div>
              <ul className="text-slate-600 space-y-1 text-sm">
                <li>• Short-term window: 5 minutes</li>
                <li>• Medium-term window: 1 hour</li>
                <li>• Long-term window: 24 hours</li>
                <li>• Baseline calculation: 7-day rolling average</li>
              </ul>
            </div>
            
            <div className="bg-green-50 rounded-lg p-4 border border-green-200">
              <div className="flex items-center space-x-3 mb-3">
                <TrendingUp className="h-6 w-6 text-green-600" />
                <h4 className="font-semibold">Statistical Metrics</h4>
              </div>
              <ul className="text-slate-600 space-y-1 text-sm">
                <li>• Moving average calculation</li>
                <li>• Standard deviation analysis</li>
                <li>• Percentile-based thresholds</li>
                <li>• Z-score anomaly detection</li>
              </ul>
            </div>
          </div>
        </div>

        <div className="mb-8">
          <h3 className="text-xl font-semibold text-slate-700 mb-4">Anomaly Detection Algorithms</h3>
          
          <div className="bg-slate-900 rounded-lg p-6 text-green-400 font-mono text-sm mb-6">
            <div className="flex items-center space-x-2 mb-4">
              <Calculator className="h-4 w-4" />
              <span className="font-semibold">Z-Score Anomaly Detection</span>
            </div>
            <pre className="whitespace-pre-wrap overflow-x-auto">
{`def calculate_z_score(current_value, historical_data):
    """
    Calculate Z-score for anomaly detection
    """
    if len(historical_data) < 30:  # Minimum samples required
        return 0
    
    mean = numpy.mean(historical_data)
    std_dev = numpy.std(historical_data)
    
    if std_dev == 0:
        return 0
    
    z_score = abs(current_value - mean) / std_dev
    return z_score

def is_anomaly(z_score, sensitivity="medium"):
    """
    Determine if Z-score indicates anomaly based on sensitivity
    """
    thresholds = {
        "low": 3.0,      # 99.7% confidence
        "medium": 2.5,   # 98.8% confidence  
        "high": 2.0,     # 95.4% confidence
        "very_high": 1.5 # 86.6% confidence
    }
    
    return z_score > thresholds.get(sensitivity, 2.5)`}
            </pre>
          </div>
        </div>

        <div className="mb-8">
          <h3 className="text-xl font-semibold text-slate-700 mb-4">Baseline Establishment</h3>
          
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div>
              <h4 className="font-semibold text-slate-700 mb-3">Network Traffic Baselines</h4>
              <div className="bg-slate-50 rounded p-4 border border-slate-200">
                <ul className="text-slate-600 space-y-2 text-sm">
                  <li>• <strong>Connection Rate:</strong> Average connections per minute by protocol</li>
                  <li>• <strong>Bandwidth Usage:</strong> Bytes per second for inbound/outbound traffic</li>
                  <li>• <strong>Port Activity:</strong> Normal port usage patterns by service</li>
                  <li>• <strong>Geo-location Patterns:</strong> Expected source/destination countries</li>
                  <li>• <strong>Protocol Distribution:</strong> Normal HTTP/HTTPS/DNS/etc. ratios</li>
                </ul>
              </div>
            </div>
            
            <div>
              <h4 className="font-semibold text-slate-700 mb-3">System Log Baselines</h4>
              <div className="bg-slate-50 rounded p-4 border border-slate-200">
                <ul className="text-slate-600 space-y-2 text-sm">
                  <li>• <strong>Authentication Events:</strong> Login frequency and timing patterns</li>
                  <li>• <strong>Process Execution:</strong> Normal application startup sequences</li>
                  <li>• <strong>File System Access:</strong> Regular file access patterns</li>
                  <li>• <strong>Error Rates:</strong> Expected error frequency baselines</li>
                  <li>• <strong>Service Activity:</strong> Normal service start/stop cycles</li>
                </ul>
              </div>
            </div>
          </div>
        </div>

        <div>
          <h3 className="text-xl font-semibold text-slate-700 mb-4">Threshold Calculation Methods</h3>
          
          <div className="bg-slate-900 rounded-lg p-6 text-green-400 font-mono text-sm">
            <div className="flex items-center space-x-2 mb-4">
              <Activity className="h-4 w-4" />
              <span className="font-semibold">Dynamic Threshold Calculation</span>
            </div>
            <pre className="whitespace-pre-wrap overflow-x-auto">
{`class ThresholdCalculator:
    def __init__(self, window_size=1440):  # 24 hours in minutes
        self.window_size = window_size
        self.data_windows = defaultdict(lambda: deque(maxlen=window_size))
    
    def update_baseline(self, metric_name: str, value: float, timestamp: float):
        """Update baseline with new data point"""
        self.data_windows[metric_name].append((timestamp, value))
    
    def calculate_dynamic_threshold(self, metric_name: str, sensitivity="medium") -> float:
        """Calculate adaptive threshold based on historical data"""
        data = list(self.data_windows[metric_name])
        
        if len(data) < 30:
            return self.get_default_threshold(metric_name)
        
        values = [point[1] for point in data[-168:]]  # Last week
        
        mean = numpy.mean(values)
        std_dev = numpy.std(values)
        percentile_95 = numpy.percentile(values, 95)
        
        # Combine statistical approaches for robust threshold
        statistical_threshold = mean + (2.5 * std_dev)
        percentile_threshold = percentile_95 * 1.2
        
        # Use the more conservative threshold
        return min(statistical_threshold, percentile_threshold)
    
    def detect_trend_anomaly(self, metric_name: str, lookback_periods=12) -> bool:
        """Detect if current trend deviates from normal patterns"""
        data = list(self.data_windows[metric_name])
        
        if len(data) < lookback_periods * 2:
            return False
        
        recent_avg = numpy.mean([point[1] for point in data[-lookback_periods:]])
        historical_avg = numpy.mean([point[1] for point in data[:-lookback_periods]])
        
        if historical_avg == 0:
            return recent_avg > 0
        
        change_ratio = recent_avg / historical_avg
        return change_ratio > 3.0 or change_ratio < 0.3`}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
}