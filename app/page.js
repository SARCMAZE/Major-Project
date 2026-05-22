"use client";

import { useState, useEffect, useRef } from "react";

export default function Home() {
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);
  const [autoRefresh, setAutoRefresh] = useState(false);
  const refreshIntervalRef = useRef(null);

  // Poll function
  const processAlerts = async (isBackground = false) => {
    if (!isBackground) {
      setLoading(true);
      setError(null);
    }

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
      if (!isBackground) {
        setError(err.message);
      }
    } finally {
      if (!isBackground) {
        setLoading(false);
      }
    }
  };

  // Trigger initial fetch on load
  useEffect(() => {
    processAlerts();
    return () => clearInterval(refreshIntervalRef.current);
  }, []);

  // Handle auto-refresh interval
  useEffect(() => {
    if (autoRefresh) {
      refreshIntervalRef.current = setInterval(() => {
        processAlerts(true);
      }, 3000);
    } else {
      clearInterval(refreshIntervalRef.current);
    }

    return () => clearInterval(refreshIntervalRef.current);
  }, [autoRefresh]);

  const getScoreColor = (score) => {
    if (score >= 85) return "text-rose-500 border-rose-500 shadow-rose-500/20";
    if (score >= 70) return "text-amber-500 border-amber-500 shadow-amber-500/20";
    return "text-cyan-500 border-cyan-500 shadow-cyan-500/20";
  };

  const getSeverityBadgeColor = (severity) => {
    if (severity === "HIGH") return "bg-rose-950/50 text-rose-400 border-rose-800/60";
    if (severity === "MEDIUM") return "bg-amber-950/50 text-amber-400 border-amber-800/60";
    return "bg-cyan-950/50 text-cyan-400 border-cyan-800/60";
  };

  // Helper to determine if a stream has had active alerts in the current list
  const isStreamActive = (streamName) => {
    if (!results || results.length === 0) return false;
    return results.some(r => r.original_alert.label.toLowerCase().includes(streamName.toLowerCase()));
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 font-mono p-4 md:p-8 selection:bg-cyan-500/30 relative overflow-hidden">
      
      {/* Background Decorative Grid */}
      <div className="absolute inset-0 bg-[linear-gradient(to_right,#0f172a_1px,transparent_1px),linear-gradient(to_bottom,#0f172a_1px,transparent_1px)] bg-[size:4rem_4rem] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_0%,#000_70%,transparent_100%)] opacity-35 pointer-events-none"></div>

      <div className="max-w-6xl mx-auto space-y-8 relative z-10">
        
        {/* Terminal Header */}
        <header className="bg-slate-900/40 backdrop-blur-md border border-slate-800 p-6 rounded-2xl shadow-xl flex flex-col md:flex-row items-start md:items-center justify-between gap-6 relative overflow-hidden">
          <div className="absolute top-0 left-0 w-full h-[2px] bg-gradient-to-r from-transparent via-cyan-500 to-transparent"></div>
          <div>
            <div className="flex items-center gap-3">
              <span className="relative flex h-3 w-3">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-3 w-3 bg-cyan-500"></span>
              </span>
              <h1 className="text-2xl md:text-3xl font-extrabold tracking-wide text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-indigo-400">
                AETHER SOC L2 TRIAGE TERMINAL
              </h1>
            </div>
            <p className="text-slate-500 mt-2 text-xs md:text-sm tracking-widest uppercase">
              Real-Time Heuristic Correlation & GenAI Security Coprocessor
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-4">
            {/* Auto Refresh Toggle */}
            <div className="flex items-center bg-slate-950/70 border border-slate-800/80 px-4 py-2.5 rounded-xl gap-3">
              <span className="text-xs uppercase text-slate-500 tracking-wider">Live Stream Ingestion</span>
              <button
                id="auto-refresh-toggle"
                onClick={() => setAutoRefresh(!autoRefresh)}
                className={`w-12 h-6 rounded-full p-0.5 transition-colors duration-300 focus:outline-none ${autoRefresh ? "bg-cyan-500" : "bg-slate-800"}`}
              >
                <div className={`bg-slate-950 w-5 h-5 rounded-full shadow-md transform transition-transform duration-300 ${autoRefresh ? "translate-x-6" : "translate-x-0"} flex items-center justify-center`}>
                  {autoRefresh && <span className="w-1.5 h-1.5 bg-cyan-400 rounded-full animate-ping"></span>}
                </div>
              </button>
            </div>

            {/* Manual Run button */}
            <button
              id="manual-triage-btn"
              onClick={() => processAlerts(false)}
              disabled={loading}
              className="px-5 py-3 bg-gradient-to-r from-cyan-950/30 to-indigo-950/30 hover:from-cyan-900/40 hover:to-indigo-900/40 text-cyan-400 border border-cyan-800/60 rounded-xl shadow-[0_0_20px_rgba(6,182,212,0.15)] hover:shadow-[0_0_25px_rgba(6,182,212,0.25)] transition-all duration-300 disabled:opacity-50 disabled:cursor-not-allowed font-semibold uppercase text-xs tracking-wider"
            >
              {loading ? "Triage in progress..." : "Re-Scan Logs"}
            </button>
          </div>
        </header>

        {/* Live Stream Stream Status Grid */}
        <section className="bg-slate-900/30 border border-slate-900 p-4 rounded-xl shadow-lg">
          <div className="text-[10px] tracking-widest text-slate-500 uppercase mb-3 flex items-center justify-between">
            <span>Operational Log Stream Feeds</span>
            {autoRefresh && <span className="text-cyan-400 animate-pulse">● System Streaming Live</span>}
          </div>
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
            {[
              { name: "Network Flow", log: "network_flow.log", code: "network" },
              { name: "Web Access", log: "web_access.log", code: "web" },
              { name: "System Auth", log: "system_auth.log", code: "auth" },
              { name: "DB Audit", log: "db_audit.log", code: "db" },
              { name: "Cloud Audit", log: "cloud_trail.log", code: "cloud" }
            ].map((feed, idx) => {
              const active = isStreamActive(feed.code);
              return (
                <div key={idx} className={`border p-3 rounded-lg flex items-center justify-between bg-slate-950/40 transition-colors duration-500 ${active ? "border-rose-900/50 bg-rose-950/5" : "border-slate-800/50"}`}>
                  <div>
                    <div className="text-xs font-bold text-slate-300">{feed.name}</div>
                    <div className="text-[9px] text-slate-500 mt-0.5">{feed.log}</div>
                  </div>
                  <span className="flex h-2.5 w-2.5 relative">
                    {active ? (
                      <>
                        <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-rose-400 opacity-75"></span>
                        <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-rose-500"></span>
                      </>
                    ) : (
                      <span className={`relative inline-flex rounded-full h-2.5 w-2.5 ${autoRefresh ? "bg-emerald-500 shadow-sm shadow-emerald-500/50 animate-pulse" : "bg-slate-700"}`}></span>
                    )}
                  </span>
                </div>
              );
            })}
          </div>
        </section>

        {/* Error Display */}
        {error && (
          <div className="bg-rose-950/40 border border-rose-800/60 p-4 rounded-xl text-rose-400 shadow-lg animate-in fade-in slide-in-from-top-4 duration-300">
            <h3 className="font-bold mb-1 text-sm tracking-wide">SYSTEM TRIP FAULT</h3>
            <p className="text-xs">{error}</p>
          </div>
        )}

        {/* Loading Indicator */}
        {loading && (
          <div className="flex flex-col items-center justify-center py-16 space-y-4">
            <div className="w-10 h-10 border-2 border-cyan-950 border-t-cyan-400 rounded-full animate-spin"></div>
            <p className="text-cyan-400 animate-pulse font-semibold uppercase tracking-widest text-xs">Executing Threat Intel Enrichment & L2 Triage...</p>
          </div>
        )}

        {/* No Alerts State */}
        {results && results.length === 0 && !loading && (
          <div className="bg-slate-950/40 border border-dashed border-slate-800 py-16 rounded-2xl flex flex-col items-center justify-center text-center space-y-3">
            <div className="text-4xl text-slate-700">🔒</div>
            <h3 className="font-bold text-slate-400 text-sm uppercase tracking-widest">No Alerts Flagged</h3>
            <p className="text-slate-500 text-xs max-w-sm">
              The L1 correlation daemon has not flagged any log entries exceeding threat thresholds. Set up the log generator (`sim_producer.py`) to launch threats.
            </p>
          </div>
        )}

        {/* Results Section */}
        {results && results.length > 0 && !loading && (
          <div className="space-y-10 animate-in fade-in slide-in-from-bottom-4 duration-500">
            {results.map((result, idx) => (
              <div key={idx} className="bg-slate-900/25 backdrop-blur-sm border border-slate-800/80 rounded-2xl shadow-xl overflow-hidden flex flex-col relative group transition-all duration-300 hover:border-slate-700/80 hover:shadow-2xl">
                
                {/* Visual Glow indicators matching severity */}
                <div className={`absolute left-0 top-0 bottom-0 w-[4px] bg-gradient-to-b ${
                  result.original_alert.severity === "HIGH" ? "from-rose-500 to-red-600" :
                  result.original_alert.severity === "MEDIUM" ? "from-amber-400 to-yellow-500" :
                  "from-cyan-400 to-teal-500"
                }`}></div>

                {/* Top Info Bar */}
                <div className="border-b border-slate-800/60 p-4 md:px-6 bg-slate-950/50 flex flex-wrap items-center justify-between gap-4">
                  <div className="flex items-center gap-3">
                    <span className={`text-[10px] font-extrabold uppercase px-2.5 py-1 rounded border tracking-widest ${getSeverityBadgeColor(result.original_alert.severity)}`}>
                      {result.original_alert.severity} SEVERITY
                    </span>
                    <span className="text-[10px] text-slate-500 uppercase tracking-widest">FLOW ID: {result.original_alert["flow id"]}</span>
                  </div>
                  <div className="text-[10px] text-slate-400 font-semibold bg-slate-900/80 px-3 py-1 rounded-md border border-slate-800/70" suppressHydrationWarning>
                    TIMESTAMP: {result.original_alert.timestamp}
                  </div>
                </div>

                <div className="p-6 space-y-6">
                  {/* Alert Raw Info Row */}
                  <div className="grid grid-cols-1 md:grid-cols-4 gap-4 p-4 bg-slate-950/70 rounded-xl border border-slate-800/50">
                    <div>
                      <span className="block text-[10px] text-slate-500 uppercase tracking-wider mb-1">Attacker Host IP</span>
                      <span className="text-sm font-bold text-rose-400 drop-shadow-[0_0_10px_rgba(244,63,94,0.15)]">{result.original_alert["source ip"]}</span>
                    </div>
                    <div>
                      <span className="block text-[10px] text-slate-500 uppercase tracking-wider mb-1">Target Resource IP</span>
                      <span className="text-sm font-bold text-indigo-400">{result.original_alert["destination ip"]}</span>
                    </div>
                    <div>
                      <span className="block text-[10px] text-slate-500 uppercase tracking-wider mb-1">L1 Threat Score</span>
                      <span className="text-sm font-bold text-slate-200">{result.original_alert.l1_score} <span className="text-[10px] text-slate-500">/ 12</span></span>
                    </div>
                    <div className="md:col-span-1">
                      <span className="block text-[10px] text-slate-500 uppercase tracking-wider mb-1">Correlated Heuristic Signature</span>
                      <span className="text-xs font-bold text-slate-100 bg-slate-900 px-2 py-0.5 rounded border border-slate-800/60 inline-block mt-0.5">{result.original_alert.label}</span>
                    </div>
                  </div>

                  {/* L2 Diagnostics Row */}
                  <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                    {/* Ring score dashboard */}
                    <div className="bg-slate-950/50 border border-slate-800/60 rounded-xl p-5 flex flex-col items-center justify-center relative overflow-hidden group">
                      <h4 className="text-[10px] text-slate-500 uppercase tracking-widest mb-3">L2 Risk Factor</h4>
                      <div className="relative flex items-center justify-center w-28 h-28">
                        <div className="absolute inset-0 rounded-full border-4 border-slate-800/50"></div>
                        <div className={`absolute inset-0 rounded-full border-4 ${getScoreColor(result.analysis.score)} shadow-[0_0_15px_currentColor] border-t-transparent border-l-transparent`}></div>
                        <span className={`text-3xl font-black ${getScoreColor(result.analysis.score)}`}>
                          {result.analysis.score}
                        </span>
                      </div>
                      <span className="text-xs font-bold text-slate-300 mt-4 tracking-wider uppercase">{result.analysis.cat}</span>
                    </div>

                    {/* Context Narrative */}
                    <div className="bg-slate-950/50 border border-slate-800/60 rounded-xl p-5 lg:col-span-2 flex flex-col justify-between">
                      <div>
                        <h4 className="text-[10px] text-indigo-400 uppercase tracking-widest mb-2 font-extrabold">GenAI Security Summary Context</h4>
                        <p className="text-xs md:text-sm text-slate-300 leading-relaxed font-sans mt-2">
                          {result.analysis.ctx}
                        </p>
                      </div>

                      {/* Threat Intel Sub-Box */}
                      <div className="mt-6 pt-4 border-t border-slate-800/40 flex flex-wrap items-center gap-4">
                        <div className="bg-slate-900/60 px-3 py-1.5 rounded-lg border border-slate-800/60 text-[10px] flex items-center gap-2">
                          <span className="text-slate-500 uppercase">Threat Domain:</span>
                          <span className="text-yellow-400 font-bold">{result.threat_intel.domain}</span>
                        </div>
                        <div className="bg-slate-900/60 px-3 py-1.5 rounded-lg border border-slate-800/60 text-[10px] flex items-center gap-2">
                          <span className="text-slate-500 uppercase">Abuse Probability:</span>
                          <span className={`font-bold ${result.threat_intel.abuse > 80 ? "text-rose-400 animate-pulse" : "text-slate-300"}`}>
                            {result.threat_intel.abuse}%
                          </span>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Actions & Remedies */}
                  <div className="bg-slate-950/40 border border-slate-850/60 rounded-xl p-5 relative">
                    <div className="absolute top-0 left-0 w-[2px] h-full bg-emerald-500"></div>
                    <h4 className="text-[10px] text-emerald-400 uppercase tracking-widest mb-3 font-extrabold">Automated Remediation Playbook</h4>
                    <ul className="space-y-2.5">
                      {result.analysis.remedy?.map((remedyItem, index) => (
                        <li key={index} className="flex items-start gap-3">
                          <span className="text-emerald-500 text-xs mt-0.5">✔</span>
                          <span className="text-xs text-slate-300 font-sans leading-relaxed">{remedyItem}</span>
                        </li>
                      ))}
                    </ul>
                  </div>

                  {/* Raw System Metrics Log Drawer */}
                  <details className="bg-slate-950/80 border border-slate-800/80 rounded-xl overflow-hidden group">
                    <summary className="p-3.5 cursor-pointer text-slate-500 hover:text-cyan-400 transition-colors font-semibold text-[10px] uppercase tracking-widest flex items-center justify-between">
                      <span>View Correlated Log Payload</span>
                      <span className="text-[9px] group-open:rotate-180 transition-transform">▼</span>
                    </summary>
                    <div className="p-4 border-t border-slate-800/60 bg-black/40 overflow-x-auto">
                      <pre className="text-[10px] text-teal-400/80 leading-relaxed">
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
