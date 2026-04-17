"use client";

import { useState } from "react";

export default function Home() {
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);

  const processAlerts = async () => {
    setLoading(true);
    setResults(null);
    setError(null);

    try {
      const response = await fetch("/api/analyze", {
        method: "POST",
      });

      const data = await response.json();
      
      if (!response.ok) {
        throw new Error(data.details || data.error || "Failed to process alerts");
      }

      setResults(data);
    } catch (err) {
      console.error(err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const getScoreColor = (score) => {
    if (score > 75) return "text-red-500 shadow-red-500/20";
    if (score > 50) return "text-yellow-500 shadow-yellow-500/20";
    return "text-green-500 shadow-green-500/20";
  };

  return (
    <div className="min-h-screen bg-gray-950 text-gray-300 font-mono p-8 selection:bg-cyan-500/30">
      <div className="max-w-5xl mx-auto space-y-8">
        
        {/* Header Section */}
        <header className="border-b border-gray-800 pb-6 flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-cyan-400 tracking-tight flex items-center gap-3">
              <span className="w-3 h-3 rounded-full bg-cyan-400 animate-pulse"></span>
              SOC L2 Triage Terminal
            </h1>
            <p className="text-gray-500 mt-2 text-sm">Automated Threat Analysis & Incident Response</p>
          </div>
          <button
            onClick={processAlerts}
            disabled={loading}
            className="px-6 py-3 bg-cyan-900/30 hover:bg-cyan-900/50 text-cyan-400 border border-cyan-800/50 rounded-lg shadow-[0_0_15px_rgba(34,211,238,0.15)] transition-all disabled:opacity-50 disabled:cursor-not-allowed hover:shadow-[0_0_20px_rgba(34,211,238,0.3)] font-semibold uppercase text-sm tracking-wider"
          >
            {loading ? "Analyzing Dataset..." : "Process Dataset"}
          </button>
        </header>

        {/* Error Display */}
        {error && (
          <div className="bg-red-900/30 border border-red-800 p-4 rounded-lg text-red-400">
            <h3 className="font-bold mb-1">Error Processing Alerts</h3>
            <p className="text-sm">{error}</p>
          </div>
        )}

        {/* Loading Indicator */}
        {loading && (
          <div className="flex flex-col items-center justify-center py-12 space-y-4">
            <div className="w-12 h-12 border-4 border-cyan-900 border-t-cyan-400 rounded-full animate-spin"></div>
            <p className="text-cyan-400 animate-pulse font-semibold uppercase tracking-widest text-sm">Connecting to Threat Intel & Analyzing Data...</p>
          </div>
        )}

        {/* Results Section */}
        {results && !loading && (
          <div className="space-y-12 animate-in fade-in slide-in-from-bottom-4 duration-500">
            {results.map((result, idx) => (
              <div key={idx} className="space-y-6 pb-12 border-b border-gray-800 last:border-0 relative">
                <div className="absolute top-0 left-0 w-2 h-full bg-gray-800 rounded-full"></div>
                
                <div className="pl-6 space-y-6">
                  {/* Input Data Section for this alert */}
                  <section className="bg-gray-900 border border-gray-800 p-6 rounded-lg shadow-lg relative overflow-hidden group">
                    <div className="absolute top-0 left-0 w-1 h-full bg-cyan-600/50 group-hover:bg-cyan-400 transition-colors"></div>
                    <div className="flex justify-between items-center mb-4 border-b border-gray-800/50 pb-2">
                      <h2 className="text-lg text-cyan-500 font-semibold uppercase tracking-widest">L1 Raw Alert Data</h2>
                      <span className="text-xs text-gray-500 font-mono">FLOW ID: {result.original_alert["flow id"]}</span>
                    </div>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                      <div>
                        <span className="block text-gray-500 mb-1">Timestamp</span>
                        <span className="text-gray-200" suppressHydrationWarning>{result.original_alert.timestamp}</span>
                      </div>
                      <div>
                        <span className="block text-gray-500 mb-1">Source IP</span>
                        <span className="text-red-400">{result.original_alert["source ip"]}</span>
                      </div>
                      <div>
                        <span className="block text-gray-500 mb-1">Dest IP</span>
                        <span className="text-cyan-400">{result.original_alert["destination ip"]}</span>
                      </div>
                      <div>
                        <span className="block text-gray-500 mb-1">L1 Score</span>
                        <span className="text-gray-200">{result.original_alert.l1_score}</span>
                      </div>
                      <div className="col-span-2 md:col-span-4">
                        <span className="block text-gray-500 mb-1">Label</span>
                        <span className="text-gray-200 bg-gray-800 px-3 py-1 rounded inline-block">{result.original_alert.label}</span>
                      </div>
                    </div>
                  </section>

                  <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                    {/* Risk Score Widget */}
                    <div className="bg-gray-900 border border-gray-800 p-6 rounded-lg flex flex-col items-center justify-center shadow-lg relative overflow-hidden group">
                      <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-current to-transparent opacity-20"></div>
                      <h3 className="text-gray-500 text-sm uppercase tracking-widest mb-2">Triage Risk Score</h3>
                      <div className={`text-7xl font-bold ${getScoreColor(result.analysis.score)} drop-shadow-lg`}>
                        {result.analysis.score}
                      </div>
                      <div className="mt-4 text-sm text-gray-400 uppercase tracking-wider">{result.analysis.cat}</div>
                    </div>

                    {/* Context Summary */}
                    <div className="bg-gray-900 border border-gray-800 p-6 rounded-lg md:col-span-2 shadow-lg relative group">
                      <div className="absolute top-0 left-0 w-1 h-full bg-purple-600/50 group-hover:bg-purple-400 transition-colors"></div>
                      <h3 className="text-purple-400 text-sm uppercase tracking-widest mb-4 border-b border-gray-800/50 pb-2">Analysis Context</h3>
                      <p className="text-gray-300 leading-relaxed">
                        {result.analysis.ctx}
                      </p>
                      
                      <div className="mt-6 flex items-center gap-4 text-xs">
                        <div className="bg-gray-800 px-3 py-1.5 rounded flex items-center gap-2">
                          <span className="text-gray-500">Intel Domain:</span>
                          <span className="text-yellow-400">{result.threat_intel.domain}</span>
                        </div>
                        <div className="bg-gray-800 px-3 py-1.5 rounded flex items-center gap-2">
                          <span className="text-gray-500">Abuse Confidence:</span>
                          <span className="text-red-400">{result.threat_intel.abuse}%</span>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Recommendations */}
                  <div className="bg-gray-900 border border-gray-800 p-6 rounded-lg shadow-lg relative group">
                    <div className="absolute top-0 left-0 w-1 h-full bg-green-600/50 group-hover:bg-green-400 transition-colors"></div>
                    <h3 className="text-green-400 text-sm uppercase tracking-widest mb-4 border-b border-gray-800/50 pb-2">Recommended Remediation</h3>
                    <ul className="space-y-3">
                      {result.analysis.remedy?.map((item, index) => (
                        <li key={index} className="flex items-start gap-3">
                          <span className="text-green-500 mt-1">▶</span>
                          <span className="text-gray-300">{item}</span>
                        </li>
                      ))}
                    </ul>
                  </div>

                  {/* Raw JSON Details */}
                  <details className="bg-black/50 border border-gray-800 rounded-lg group overflow-hidden">
                    <summary className="p-4 cursor-pointer text-gray-500 hover:text-cyan-400 transition-colors font-semibold text-sm uppercase tracking-wider flex items-center justify-between">
                      View Raw JSON Payload
                      <span className="text-gray-600 group-open:rotate-180 transition-transform">▼</span>
                    </summary>
                    <div className="p-4 border-t border-gray-800 bg-black/80 overflow-x-auto">
                      <pre className="text-xs text-green-400/80">
                        {JSON.stringify(result, null, 2)}
                      </pre>
                    </div>
                  </details>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
