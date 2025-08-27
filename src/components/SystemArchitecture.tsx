import React from 'react';
import { Network, Database, Shield, Monitor, AlertCircle } from 'lucide-react';

export function SystemArchitecture() {
  return (
    <div className="space-y-8">
      <div className="bg-white rounded-lg shadow-sm border border-slate-200 p-6">
        <h2 className="text-2xl font-bold text-slate-800 mb-6">System Architecture</h2>
        
        <div className="mb-8">
          <h3 className="text-xl font-semibold text-slate-700 mb-4">Component Overview</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            <div className="bg-blue-50 rounded-lg p-4 border border-blue-200">
              <div className="flex items-center space-x-3 mb-3">
                <Monitor className="h-6 w-6 text-blue-600" />
                <h4 className="font-semibold">Data Collectors</h4>
              </div>
              <p className="text-slate-600 text-sm">
                Log file monitors, network packet analyzers, and system event watchers.
              </p>
            </div>
            
            <div className="bg-green-50 rounded-lg p-4 border border-green-200">
              <div className="flex items-center space-x-3 mb-3">
                <Database className="h-6 w-6 text-green-600" />
                <h4 className="font-semibold">Processing Engine</h4>
              </div>
              <p className="text-slate-600 text-sm">
                Rule-based detection engine with statistical analysis and pattern matching.
              </p>
            </div>
            
            <div className="bg-orange-50 rounded-lg p-4 border border-orange-200">
              <div className="flex items-center space-x-3 mb-3">
                <AlertCircle className="h-6 w-6 text-orange-600" />
                <h4 className="font-semibold">Alert Manager</h4>
              </div>
              <p className="text-slate-600 text-sm">
                Multi-channel notification system with severity-based routing.
              </p>
            </div>
          </div>
        </div>

        <div className="mb-8">
          <h3 className="text-xl font-semibold text-slate-700 mb-4">Architecture Diagram</h3>
          <div className="bg-slate-100 rounded-lg p-8 border border-slate-200">
            <div className="flex flex-col space-y-6">
              {/* Data Sources */}
              <div className="text-center">
                <h4 className="font-semibold text-slate-700 mb-4">Data Sources</h4>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="bg-white rounded p-3 shadow-sm border">
                    <Network className="h-5 w-5 text-blue-500 mx-auto mb-2" />
                    <div className="text-xs font-medium">Network Traffic</div>
                  </div>
                  <div className="bg-white rounded p-3 shadow-sm border">
                    <Shield className="h-5 w-5 text-green-500 mx-auto mb-2" />
                    <div className="text-xs font-medium">System Logs</div>
                  </div>
                  <div className="bg-white rounded p-3 shadow-sm border">
                    <Monitor className="h-5 w-5 text-purple-500 mx-auto mb-2" />
                    <div className="text-xs font-medium">Application Events</div>
                  </div>
                </div>
              </div>
              
              {/* Processing Layer */}
              <div className="text-center">
                <div className="flex justify-center mb-2">
                  <div className="w-0.5 h-8 bg-slate-300"></div>
                </div>
                <h4 className="font-semibold text-slate-700 mb-4">Processing Layer</h4>
                <div className="bg-blue-600 text-white rounded-lg p-4 shadow-md">
                  <Database className="h-6 w-6 mx-auto mb-2" />
                  <div className="text-sm font-medium">Zero-Day Detection Engine</div>
                  <div className="text-xs opacity-80 mt-1">Rule Engine + Statistical Analysis</div>
                </div>
              </div>
              
              {/* Output */}
              <div className="text-center">
                <div className="flex justify-center mb-2">
                  <div className="w-0.5 h-8 bg-slate-300"></div>
                </div>
                <h4 className="font-semibold text-slate-700 mb-4">Alert & Response</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="bg-white rounded p-3 shadow-sm border border-red-200">
                    <AlertCircle className="h-5 w-5 text-red-500 mx-auto mb-2" />
                    <div className="text-xs font-medium">Security Alerts</div>
                  </div>
                  <div className="bg-white rounded p-3 shadow-sm border border-blue-200">
                    <Monitor className="h-5 w-5 text-blue-500 mx-auto mb-2" />
                    <div className="text-xs font-medium">Dashboard</div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div>
          <h3 className="text-xl font-semibold text-slate-700 mb-4">Data Flow Architecture</h3>
          <div className="bg-slate-50 rounded-lg p-6 border border-slate-200">
            <div className="grid grid-cols-1 lg:grid-cols-4 gap-4 text-center">
              <div className="bg-white rounded p-4 shadow-sm">
                <h4 className="font-semibold text-slate-700 text-sm mb-2">1. Collection</h4>
                <p className="text-xs text-slate-600">Raw log ingestion and network packet capture</p>
              </div>
              <div className="bg-white rounded p-4 shadow-sm">
                <h4 className="font-semibold text-slate-700 text-sm mb-2">2. Normalization</h4>
                <p className="text-xs text-slate-600">Parse and standardize data formats</p>
              </div>
              <div className="bg-white rounded p-4 shadow-sm">
                <h4 className="font-semibold text-slate-700 text-sm mb-2">3. Analysis</h4>
                <p className="text-xs text-slate-600">Rule matching and statistical evaluation</p>
              </div>
              <div className="bg-white rounded p-4 shadow-sm">
                <h4 className="font-semibold text-slate-700 text-sm mb-2">4. Response</h4>
                <p className="text-xs text-slate-600">Alert generation and notification</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}