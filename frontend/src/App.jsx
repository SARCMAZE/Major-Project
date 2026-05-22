import { useEffect, useMemo, useState, useRef } from "react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { MetricCard } from "./components/MetricCard";
import { Panel } from "./components/Panel";

const API_BASE_URL = "http://localhost:8000/api";
const WS_BASE_URL = "ws://localhost:8000/api/ws/alerts";

const severityColors = {
  CRITICAL: "#fb7185", // red
  HIGH: "#f97316",     // orange
  MEDIUM: "#facc15",   // yellow
  LOW: "#22c55e",      // green
  INFO: "#38bdf8",     // blue
};

const sourceNames = {
  network: "Network Flow",
  web: "Web Request",
  auth: "System Auth",
  db: "Database Audit",
  cloud: "Cloud Trail",
};

const chartPalette = ["#3dd9d6", "#a3e635", "#fb7185", "#f5e6c8", "#c084fc", "#38bdf8"];

function formatNumber(value) {
  if (value === null || value === undefined || Number.isNaN(value)) {
    return "N/A";
  }
  return Intl.NumberFormat("en-US", { maximumFractionDigits: 1 }).format(value);
}

function App() {
  const [alerts, setAlerts] = useState([]);
  const [ipStates, setIpStates] = useState([]);
  const [metrics, setMetrics] = useState({
    total_alerts: 0,
    active_alerts: 0,
    resolved_alerts: 0,
    alerts_per_second: 0.0,
    mean_time_to_detect: 0.8,
    mean_time_to_respond: 142.5,
    analyst_workload_index: 10.0,
    average_threat_risk: 0.0,
  });
  const [distributions, setDistributions] = useState({
    source: { network: 0, web: 0, auth: 0, db: 0, cloud: 0 },
    severity: { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 },
  });

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [connectionStatus, setConnectionStatus] = useState("connecting");
  const [selectedAlertId, setSelectedAlertId] = useState(null);

  // Filters State
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedSeverities, setSelectedSeverities] = useState([]);
  const [selectedSources, setSelectedSources] = useState([]);
  const [showResolved, setShowResolved] = useState(true);

  // Emulator Control State
  const [emulatorRunning, setEmulatorRunning] = useState(true);
  const [emulatorSpeed, setEmulatorSpeed] = useState(1.2);

  const socketRef = useRef(null);

  // Fetch initial REST data
  const fetchData = async () => {
    try {
      const [alertsRes, metricsRes, ipRes] = await Promise.all([
        fetch(`${API_BASE_URL}/alerts?limit=100`),
        fetch(`${API_BASE_URL}/metrics`),
        fetch(`${API_BASE_URL}/ip-states?limit=15`),
      ]);

      if (!alertsRes.ok || !metricsRes.ok || !ipRes.ok) {
        throw new Error("Failed to load backend telemetry resources.");
      }

      const alertsData = await alertsRes.json();
      const metricsData = await metricsRes.json();
      const ipData = await ipRes.json();

      setAlerts(alertsData);
      setMetrics(metricsData.metrics);
      setDistributions(metricsData.distributions);
      setIpStates(ipData);
      setError("");
    } catch (err) {
      console.error("Initial fetch error:", err);
      setError("Unable to connect to FastAPI SOC API server. Please check backend server status.");
    } finally {
      setLoading(false);
    }
  };

  // Re-fetch metrics and IP reputations dynamically on new alerts or resolution
  const refreshStats = async () => {
    try {
      const [metricsRes, ipRes] = await Promise.all([
        fetch(`${API_BASE_URL}/metrics`),
        fetch(`${API_BASE_URL}/ip-states?limit=15`),
      ]);
      if (metricsRes.ok && ipRes.ok) {
        const metricsData = await metricsRes.json();
        const ipData = await ipRes.json();
        setMetrics(metricsData.metrics);
        setDistributions(metricsData.distributions);
        setIpStates(ipData);
      }
    } catch (err) {
      console.error("Error refreshing dashboard stats:", err);
    }
  };

  // Resolve Alert Event Handlers
  const handleResolveAlert = async (alertId) => {
    try {
      const res = await fetch(`${API_BASE_URL}/alerts/${alertId}/resolve`, {
        method: "POST",
      });
      if (res.ok) {
        // Mark as resolved in local UI state
        setAlerts((current) =>
          current.map((a) => (a.id === alertId ? { ...a, status: "resolved" } : a))
        );
        refreshStats();
      } else {
        alert("Error while trying to resolve selected alert.");
      }
    } catch (err) {
      console.error("Resolve error:", err);
    }
  };

  // Emulator Toggle Handler
  const handleControlEmulator = async (isRunning, speedVal) => {
    try {
      const res = await fetch(`${API_BASE_URL}/emulator/control`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ running: isRunning, speed: speedVal }),
      });
      if (res.ok) {
        setEmulatorRunning(isRunning);
        if (speedVal !== undefined) {
          setEmulatorSpeed(speedVal);
        }
      }
    } catch (err) {
      console.error("Emulator control error:", err);
    }
  };

  // WebSocket Connection & Reconnection Loop
  useEffect(() => {
    fetchData();

    function connectWebSocket() {
      setConnectionStatus("connecting");
      const ws = new WebSocket(WS_BASE_URL);
      socketRef.current = ws;

      ws.onopen = () => {
        console.info("WebSocket connected to live SOC pipeline.");
        setConnectionStatus("connected");
        setError("");
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          
          if (data.event_type === "bootstrap") {
            setAlerts(data.alerts);
          } else {
            // It is an individual real-time alert dict
            setAlerts((current) => {
              // Prepend alert if it's new
              const exists = current.some((a) => a.id === data.id);
              if (exists) return current;
              
              const updated = [data, ...current];
              // Cap at 150 items to keep DOM performant
              return updated.slice(0, 150);
            });
            // Automatically trigger quick UI metrics refresh
            refreshStats();
          }
        } catch (err) {
          console.error("Error parsing socket frame:", err);
        }
      };

      ws.onclose = () => {
        console.info("WebSocket disconnected. Retrying in 2 seconds...");
        setConnectionStatus("disconnected");
        // Attempt clean reconnect after 2 seconds
        setTimeout(connectWebSocket, 2000);
      };

      ws.onerror = (err) => {
        console.error("WebSocket encountered an error:", err);
        ws.close();
      };
    }

    connectWebSocket();

    return () => {
      if (socketRef.current) {
        socketRef.current.close();
      }
    };
  }, []);

  // Compute filters list dynamically in React
  const filteredAlerts = useMemo(() => {
    return alerts.filter((a) => {
      // 1. Search Query (matches IP, Attack Type, or log narrative)
      if (searchQuery) {
        const query = searchQuery.toLowerCase();
        const matchesSearch =
          a.source_ip.toLowerCase().includes(query) ||
          a.destination_ip.toLowerCase().includes(query) ||
          a.attack_type.toLowerCase().includes(query) ||
          (a.explanation && a.explanation.toLowerCase().includes(query)) ||
          a.source.toLowerCase().includes(query);
        if (!matchesSearch) return false;
      }

      // 2. Severity Filters
      if (selectedSeverities.length > 0) {
        if (!selectedSeverities.includes(a.severity)) return false;
      }

      // 3. Source Filters
      if (selectedSources.length > 0) {
        if (!selectedSources.includes(a.source)) return false;
      }

      // 4. Resolution Status
      if (!showResolved && a.status === "resolved") {
        return false;
      }

      return true;
    });
  }, [alerts, searchQuery, selectedSeverities, selectedSources, showResolved]);

  // Selected priority alert details
  const selectedAlert = useMemo(() => {
    if (selectedAlertId) {
      return alerts.find((a) => a.id === selectedAlertId);
    }
    return filteredAlerts[0] || null;
  }, [alerts, filteredAlerts, selectedAlertId]);

  // Severity Mix breakdown values
  const severityChartData = useMemo(() => {
    return Object.entries(distributions.severity).map(([name, value]) => ({ name, value }));
  }, [distributions]);

  // Source distribution values
  const sourceChartData = useMemo(() => {
    return Object.entries(distributions.source).map(([key, value]) => ({
      name: sourceNames[key] || key,
      value,
    }));
  }, [distributions]);

  // Risk Timeline values from the last 15 alerts
  const riskTimelineData = useMemo(() => {
    return [...alerts]
      .reverse()
      .slice(-15)
      .map((a) => ({
        time: new Date(a.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }),
        "Dynamic Risk": a.l1_score,
      }));
  }, [alerts]);

  // Filter helper functions
  const toggleSeverity = (sev) => {
    setSelectedSeverities((current) =>
      current.includes(sev) ? current.filter((s) => s !== sev) : [...current, sev]
    );
  };

  const toggleSource = (src) => {
    setSelectedSources((current) =>
      current.includes(src) ? current.filter((s) => s !== src) : [...current, src]
    );
  };

  const resetFilters = () => {
    setSearchQuery("");
    setSelectedSeverities([]);
    setSelectedSources([]);
    setShowResolved(true);
  };

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-950 text-slate-100 font-body">
        <div className="text-center">
          <div className="h-12 w-12 animate-spin rounded-full border-4 border-cyan border-t-transparent mx-auto mb-4"></div>
          <p className="font-display text-lg tracking-wider">BOOTSTRAPPING LIVE SOC SYSTEM...</p>
        </div>
      </div>
    );
  }

  if (error && alerts.length === 0) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-950 text-slate-100 p-8 font-body">
        <div className="glass-panel max-w-2xl p-6 text-center border-rose-500/20">
          <h1 className="font-display text-3xl text-rose-400">SOC Connection Refused</h1>
          <p className="mt-4 text-slate-300">{error}</p>
          <div className="mt-6 rounded-2xl border border-white/5 bg-white/5 p-4 text-left text-sm font-mono">
            <p className="text-cyan"># Start the FastAPI backend first:</p>
            <p className="mt-1 text-slate-100">cd backend</p>
            <p className="text-slate-100">python -m app.main</p>
            <p className="mt-3 text-cyan"># Or boot using Docker Suite:</p>
            <p className="text-slate-100">docker-compose up --build</p>
          </div>
          <button
            onClick={() => window.location.reload()}
            className="mt-6 rounded-full bg-cyan px-6 py-2.5 text-sm font-bold text-slate-950 hover:bg-cyan/90 transition"
          >
            Retry Connection
          </button>
        </div>
      </div>
    );
  }

  return (
    <main className="grid-pattern min-h-screen text-slate-100 font-body bg-ink pb-12">
      {/* Top Banner Navigation */}
      <header className="sticky top-0 z-40 w-full border-b border-white/10 bg-slate-950/80 backdrop-blur-md px-6 py-4">
        <div className="mx-auto flex max-w-[1600px] items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-tr from-cyan to-lime">
              <svg className="h-6 w-6 text-slate-950" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
            </div>
            <div>
              <h1 className="font-display text-xl tracking-tight text-white flex items-center gap-2">
                Aegis-X <span className="text-xs bg-cyan/15 text-cyan border border-cyan/20 px-2 py-0.5 rounded font-mono font-semibold uppercase tracking-wider">Enterprise SOC</span>
              </h1>
              <p className="text-xs text-slate-400">Autonomous Multi-Agent Threat Triage & ML Anomaly Pipeline</p>
            </div>
          </div>
          
          {/* Connection Status Badge */}
          <div className="flex items-center gap-6">
            <div className="flex items-center gap-2 text-xs font-mono">
              <span className={`h-2.5 w-2.5 rounded-full ${
                connectionStatus === "connected" ? "bg-lime animate-pulse" :
                connectionStatus === "connecting" ? "bg-yellow-400 animate-bounce" : "bg-rose-500 animate-ping"
              }`} />
              <span className="text-slate-300">
                Live Server Pipeline: {
                  connectionStatus === "connected" ? "SYNCED" :
                  connectionStatus === "connecting" ? "CONNECTING..." : "DISCONNECTED (RETRYING)"
                }
              </span>
            </div>
          </div>
        </div>
      </header>

      <div className="mx-auto flex w-full max-w-[1600px] flex-col lg:flex-row gap-6 px-4 py-8 lg:px-6">
        
        {/* SIDEBAR: CONTROL TOWER */}
        <aside className="glass-panel w-full lg:w-[320px] shrink-0 p-5 self-start lg:sticky lg:top-[96px]">
          <div className="flex items-center justify-between">
            <p className="font-display text-xl text-white">Control Tower</p>
            <button onClick={resetFilters} className="text-xs text-cyan hover:underline">Reset</button>
          </div>
          
          <div className="mt-6 space-y-6 text-sm">
            {/* Real-time Threat Simulator Control panel */}
            <div className="rounded-2xl border border-white/5 bg-slate-950/60 p-4">
              <p className="font-display text-sm text-white mb-3">Simulation Engine</p>
              <div className="flex items-center justify-between mb-4">
                <span className="text-xs text-slate-400">Emulator Status:</span>
                <button
                  onClick={() => handleControlEmulator(!emulatorRunning)}
                  className={`rounded-full px-3 py-1 text-xs font-semibold uppercase tracking-wider transition ${
                    emulatorRunning
                      ? "bg-lime/20 text-lime border border-lime/30"
                      : "bg-rose-500/20 text-rose-400 border border-rose-500/30"
                  }`}
                >
                  {emulatorRunning ? "Active" : "Paused"}
                </button>
              </div>
              <div>
                <div className="flex justify-between text-xs text-slate-400 mb-1">
                  <span>Log Flow Rate:</span>
                  <span className="text-cyan font-mono">{emulatorSpeed.toFixed(1)}s interval</span>
                </div>
                <input
                  type="range"
                  min="0.2"
                  max="3.0"
                  step="0.1"
                  value={emulatorSpeed}
                  disabled={!emulatorRunning}
                  onChange={(e) => handleControlEmulator(true, parseFloat(e.target.value))}
                  className="w-full h-1 bg-white/10 rounded-lg appearance-none cursor-pointer accent-cyan"
                />
                <div className="flex justify-between text-[10px] text-slate-500 mt-1">
                  <span>Fast (0.2s)</span>
                  <span>Slow (3.0s)</span>
                </div>
              </div>
            </div>

            {/* Filter: Search */}
            <div>
              <label className="mb-2 block text-slate-400 font-semibold">Security Search</label>
              <div className="relative">
                <input
                  className="w-full rounded-2xl border border-white/10 bg-white/5 px-4 py-3 pl-10 text-sm text-white outline-none transition focus:border-cyan/80 focus:bg-white/10"
                  placeholder="Filter IP, query, host..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                />
                <svg className="absolute left-3.5 top-3.5 h-4.5 w-4.5 text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                </svg>
              </div>
            </div>

            {/* Filter: Sources */}
            <div>
              <p className="mb-2 text-slate-400 font-semibold">Log Source</p>
              <div className="flex flex-wrap gap-2">
                {Object.keys(sourceNames).map((src) => {
                  const active = selectedSources.includes(src);
                  return (
                    <button
                      key={src}
                      type="button"
                      onClick={() => toggleSource(src)}
                      className={`rounded-full border px-3 py-1.5 text-xs transition ${
                        active
                          ? "border-cyan bg-cyan/15 text-cyan"
                          : "border-white/10 bg-white/5 text-slate-300 hover:border-white/20"
                      }`}
                    >
                      {sourceNames[src]}
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Filter: Severity */}
            <div>
              <p className="mb-2 text-slate-400 font-semibold">Filter Severity</p>
              <div className="flex flex-wrap gap-2">
                {Object.keys(severityColors).map((sev) => {
                  const active = selectedSeverities.includes(sev);
                  return (
                    <button
                      key={sev}
                      type="button"
                      onClick={() => toggleSeverity(sev)}
                      className={`rounded-full border px-3 py-1.5 text-xs transition`}
                      style={{
                        borderColor: active ? severityColors[sev] : "rgba(255, 255, 255, 0.1)",
                        backgroundColor: active ? `${severityColors[sev]}25` : "rgba(255, 255, 255, 0.05)",
                        color: active ? severityColors[sev] : "#cbd5e1"
                      }}
                    >
                      {sev}
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Switch: Show Resolved */}
            <label className="flex items-center gap-3 rounded-2xl border border-white/10 bg-white/5 px-4 py-3 cursor-pointer">
              <input
                type="checkbox"
                checked={showResolved}
                onChange={(e) => setShowResolved(e.target.checked)}
                className="rounded border-white/10 bg-white/5 text-cyan focus:ring-0"
              />
              <span className="text-slate-300">Display Resolved Incidents</span>
            </label>
          </div>
        </aside>

        {/* MAIN BODY CONTENTS */}
        <section className="min-w-0 flex-1 space-y-6">
          
          {/* SYSTEM-WIDE REAL-TIME SOC METRICS */}
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
            <MetricCard title="Telemetry Total" value={metrics.total_alerts} accent="cyan" subtitle="Total flagged threats" />
            <MetricCard title="Active Threats" value={metrics.active_alerts} accent="ember" subtitle="Unresolved active triage" />
            <MetricCard title="Live Flow Rate" value={`${metrics.alerts_per_second} p/s`} accent="lime" subtitle="Real-time incident feed velocity" />
            <MetricCard title="Mean Time To Detect" value={`${metrics.mean_time_to_detect}s`} accent="cyan" subtitle="Average agent normalization latency" />
            <MetricCard title="Mean Time To Respond" value={`${metrics.mean_time_to_respond}s`} accent="lime" subtitle="Average AI mitigation deployment" />
          </div>

          <div className="grid gap-6 xl:grid-cols-3">
            {/* ANALYST COGNITIVE LOAD GAUGE CARD */}
            <Panel title="Analyst Workload Index" subtitle="Cognitive load index derived from active threat weights" className="col-span-1">
              <div className="flex flex-col items-center justify-center py-6">
                <div className="relative flex items-center justify-center h-40 w-40">
                  {/* Gauge Arc outer */}
                  <svg className="w-full h-full transform -rotate-90">
                    <circle cx="80" cy="80" r="64" stroke="rgba(255,255,255,0.06)" strokeWidth="12" fill="transparent" />
                    <circle
                      cx="80"
                      cy="80"
                      r="64"
                      stroke={
                        metrics.analyst_workload_index > 75 ? "#fb7185" :
                        metrics.analyst_workload_index > 45 ? "#facc15" : "#22c55e"
                      }
                      strokeWidth="12"
                      fill="transparent"
                      strokeDasharray={2 * Math.PI * 64}
                      strokeDashoffset={(2 * Math.PI * 64) * (1 - metrics.analyst_workload_index / 100)}
                      className="transition-all duration-1000 ease-out"
                    />
                  </svg>
                  <div className="absolute text-center">
                    <p className="font-display text-4xl font-bold text-white leading-none">{metrics.analyst_workload_index}%</p>
                    <p className="text-[10px] uppercase tracking-widest text-slate-400 mt-2 font-mono">
                      {
                        metrics.analyst_workload_index > 75 ? "CRITICAL CRUSH" :
                        metrics.analyst_workload_index > 45 ? "MODERATE LOAD" : "SAFE / GREEN STATE"
                      }
                    </p>
                  </div>
                </div>
                
                {/* Dynamic alert stats summary */}
                <div className="w-full mt-6 grid grid-cols-2 gap-2 text-center text-xs">
                  <div className="rounded-xl bg-white/5 p-2">
                    <p className="text-slate-400">Total Resolved</p>
                    <p className="font-display font-semibold text-lg text-lime mt-0.5">{metrics.resolved_alerts}</p>
                  </div>
                  <div className="rounded-xl bg-white/5 p-2">
                    <p className="text-slate-400">Triage Risk Level</p>
                    <p className="font-display font-semibold text-lg text-cyan mt-0.5">{metrics.average_threat_risk}</p>
                  </div>
                </div>
              </div>
            </Panel>

            {/* REAL-TIME DYNAMIC THREAT TIMELINE */}
            <Panel title="Continuous Dynamic Risk Feed" subtitle="Sliding average score of last 15 security alerts" className="xl:col-span-2">
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={riskTimelineData}>
                    <defs>
                      <linearGradient id="liveRiskFill" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#3dd9d6" stopOpacity={0.7} />
                        <stop offset="95%" stopColor="#3dd9d6" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid stroke="rgba(255,255,255,0.06)" vertical={false} />
                    <XAxis dataKey="time" stroke="#cbd5e1" tickLine={false} axisLine={false} tick={{ fontSize: 9 }} />
                    <YAxis domain={[0, 40]} stroke="#cbd5e1" tickLine={false} axisLine={false} tick={{ fontSize: 10 }} />
                    <Tooltip contentStyle={{ backgroundColor: "#04131f", borderColor: "rgba(255,255,255,0.15)" }} />
                    <Area type="monotone" dataKey="Dynamic Risk" stroke="#3dd9d6" fill="url(#liveRiskFill)" strokeWidth={2.5} />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </Panel>
          </div>

          <div className="grid gap-6 xl:grid-cols-2">
            {/* BAR CHART: ATTACK SOURCE DISTRIBUTION */}
            <Panel title="Source Distribution" subtitle="All-time alert counts breakdown by security file context">
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={sourceChartData} margin={{ top: 12, right: 12, bottom: 8, left: 12 }}>
                    <CartesianGrid stroke="rgba(255,255,255,0.06)" horizontal={false} />
                    <XAxis type="number" stroke="#cbd5e1" axisLine={false} tickLine={false} tick={{ fontSize: 10 }} />
                    <YAxis type="category" dataKey="name" stroke="#cbd5e1" axisLine={false} tickLine={false} tick={{ fontSize: 10 }} width={90} />
                    <Tooltip contentStyle={{ backgroundColor: "#04131f", borderColor: "rgba(255,255,255,0.15)" }} />
                    <Bar dataKey="value" radius={[0, 6, 6, 0]}>
                      {sourceChartData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={chartPalette[index % chartPalette.length]} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </Panel>

            {/* PIE CHART: SEVERITY BREAKDOWN */}
            <Panel title="Severity Breakdown" subtitle="Ratio breakdown of active and historic incident profiles">
              <div className="h-64 flex items-center justify-center">
                <div className="w-[60%] h-full">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={severityChartData}
                        dataKey="value"
                        nameKey="name"
                        innerRadius={50}
                        outerRadius={75}
                        paddingAngle={3}
                      >
                        {severityChartData.map((entry) => (
                          <Cell key={`cell-${entry.name}`} fill={severityColors[entry.name] || "#94a3b8"} />
                        ))}
                      </Pie>
                      <Tooltip contentStyle={{ backgroundColor: "#04131f", borderColor: "rgba(255,255,255,0.15)" }} />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
                {/* Table legend */}
                <div className="w-[40%] space-y-2 text-xs">
                  {severityChartData.map((item) => (
                    <div key={item.name} className="flex items-center justify-between px-2 py-1 rounded bg-white/5">
                      <div className="flex items-center gap-1.5">
                        <span className="h-2 w-2 rounded-full" style={{ backgroundColor: severityColors[item.name] }} />
                        <span className="font-mono">{item.name}</span>
                      </div>
                      <span className="font-bold font-mono">{item.value}</span>
                    </div>
                  ))}
                </div>
              </div>
            </Panel>
          </div>

          {/* LOWER SECTION: INCIDENT QUEUE AND DETAILS GRID */}
          <div className="grid gap-6 xl:grid-cols-[1.4fr_1fr]">
            
            {/* INCIDENT DETAILS SCREEN */}
            <Panel title="Incident Priority Analyzer" subtitle="Detailed security summary, multi-agent evaluation, and recovery steps">
              {selectedAlert ? (
                <div className="space-y-4">
                  {/* Alert Header Badge */}
                  <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/5 pb-3">
                    <div className="flex items-center gap-3">
                      <span
                        className="rounded-full px-3 py-1 text-xs font-semibold uppercase tracking-[0.24em]"
                        style={{
                          backgroundColor: `${severityColors[selectedAlert.severity]}18`,
                          color: severityColors[selectedAlert.severity] || "#fff"
                        }}
                      >
                        {selectedAlert.severity} Badge
                      </span>
                      {selectedAlert.is_anomaly && (
                        <span className="rounded-full px-2.5 py-0.5 text-[10px] font-semibold bg-pink-500/15 text-pink-400 border border-pink-500/20 uppercase tracking-widest animate-pulse">
                          ML ANOMALY
                        </span>
                      )}
                    </div>
                    
                    <div className="flex gap-2">
                      {selectedAlert.status !== "resolved" && (
                        <button
                          onClick={() => handleResolveAlert(selectedAlert.id)}
                          className="rounded-full bg-lime text-slate-950 font-bold px-4 py-1 text-xs hover:bg-lime/90 transition shadow-md shadow-lime/10"
                        >
                          Resolve Alert
                        </button>
                      )}
                      <span className="text-xs font-mono rounded bg-white/5 px-2.5 py-1 text-slate-300">
                        DynRisk Score: {selectedAlert.l1_score}
                      </span>
                    </div>
                  </div>

                  {/* Classification Title */}
                  <div>
                    <p className="text-xs text-slate-400 uppercase tracking-widest font-mono">Incident Type</p>
                    <p className="font-display text-2xl text-white font-bold mt-0.5">{selectedAlert.attack_type}</p>
                    <p className="mt-1 text-xs text-slate-400">
                      IP: <span className="text-cyan font-mono font-semibold">{selectedAlert.source_ip}</span> to <span className="text-slate-300 font-mono font-semibold">{selectedAlert.destination_ip}</span>
                    </p>
                  </div>

                  {/* L2 Agent explanation text */}
                  <div className="rounded-2xl border border-white/5 bg-slate-950/60 p-4">
                    <p className="text-[10px] uppercase tracking-[0.24em] font-mono text-cyan">L2 Analyst Narrative</p>
                    <p className="mt-2 text-sm leading-6 text-slate-200 font-body">{selectedAlert.explanation}</p>
                  </div>

                  {/* L2 Recommendations list */}
                  <div className="rounded-2xl border border-lime/20 bg-lime/5 p-4">
                    <p className="text-[10px] uppercase tracking-[0.24em] font-mono text-lime">Mitigation & Countermeasures</p>
                    <p className="mt-2 text-sm leading-6 text-slate-200 font-body whitespace-pre-line">{selectedAlert.recommendation}</p>
                  </div>

                  {/* ML Telemetry features */}
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-center text-xs">
                    <Stat label="Source Origin" value={sourceNames[selectedAlert.source] || selectedAlert.source} />
                    <Stat label="Anomaly Probability" value={selectedAlert.is_anomaly ? `${(selectedAlert.anomaly_score * 100).toFixed(0)}%` : "N/A"} />
                    <Stat label="Trigger Status" value={selectedAlert.status.toUpperCase()} />
                    <Stat label="Occurrence" value={new Date(selectedAlert.timestamp).toLocaleTimeString()} />
                  </div>

                  {/* RAW EVENT INSPECTION VIEW */}
                  <div className="rounded-2xl border border-white/5 bg-slate-950 p-4">
                    <p className="text-[10px] uppercase tracking-[0.24em] font-mono text-slate-400 mb-2">Inspect Raw Payload</p>
                    <pre className="text-xs font-mono text-slate-300 overflow-x-auto bg-slate-900/60 rounded p-3 max-h-40 leading-5">
                      {JSON.stringify(selectedAlert.raw_payload, null, 2)}
                    </pre>
                  </div>
                </div>
              ) : (
                <div className="text-center py-12 text-slate-400">
                  <p>No active incidents flagged in database queue.</p>
                </div>
              )}
            </Panel>

            {/* ACTIVE CORRELATED IP ENGINE LIST */}
            <Panel title="Correlated Attacker Directory" subtitle="Dynamic reputation list of top attacker IPs on network">
              <div className="space-y-3 max-h-[730px] overflow-y-auto pr-1">
                {ipStates.length > 0 ? (
                  ipStates.map((state) => (
                    <div
                      key={state.ip}
                      className="rounded-2xl border border-white/5 bg-white/5 p-4 flex items-center justify-between transition hover:bg-white/10"
                    >
                      <div>
                        <p className="font-mono text-sm font-semibold text-white">{state.ip}</p>
                        <p className="text-[10px] text-slate-400 mt-1">
                          Total Event Spikes: <span className="text-cyan font-bold font-mono">{state.event_count}</span>
                        </p>
                        <div className="flex flex-wrap gap-1 mt-2">
                          {state.attack_history.slice(-3).map((hist, idx) => (
                            <span
                              key={idx}
                              className="text-[9px] font-mono px-2 py-0.5 rounded-full bg-slate-950 text-slate-300 border border-white/5"
                            >
                              {hist.source.toUpperCase()}: {hist.severity}
                            </span>
                          ))}
                        </div>
                      </div>
                      
                      <div className="text-right">
                        <span
                          className="rounded-full px-2.5 py-1 text-xs font-mono font-bold"
                          style={{
                            backgroundColor: state.risk_score >= 15.0 ? "rgba(251,113,133,0.15)" : "rgba(61,217,214,0.1)",
                            color: state.risk_score >= 15.0 ? "#fb7185" : "#3dd9d6",
                            border: state.risk_score >= 15.0 ? "1px solid rgba(251,113,133,0.25)" : "1px solid rgba(61,217,214,0.15)"
                          }}
                        >
                          Rep Score: {state.risk_score.toFixed(0)}
                        </span>
                        <p className="text-[9px] text-slate-400 mt-2 font-mono">
                          Last Seen: {new Date(state.last_seen).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                        </p>
                      </div>
                    </div>
                  ))
                ) : (
                  <p className="text-center text-slate-400 py-8">No dynamic IP entries stored.</p>
                )}
              </div>
            </Panel>
          </div>

          {/* INCIDENT QUEUE LOG TABLE LIST */}
          <Panel title="Real-time SOC Triage Alert Queue" subtitle="Chronological list of all flagged security alerts from telemetry log tailer">
            <div className="overflow-x-auto">
              <table className="min-w-full border-separate border-spacing-y-2 text-left text-sm">
                <thead className="text-slate-400 font-mono text-xs uppercase tracking-wider">
                  <tr>
                    <th className="px-4 py-2">Severity</th>
                    <th className="px-4 py-2">Incident Type</th>
                    <th className="px-4 py-2">Source IP</th>
                    <th className="px-4 py-2">Origin log</th>
                    <th className="px-4 py-2">Risk</th>
                    <th className="px-4 py-2">Status</th>
                    <th className="px-4 py-2">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredAlerts.length > 0 ? (
                    filteredAlerts.slice(0, 30).map((alert) => (
                      <tr
                        key={alert.id}
                        onClick={() => setSelectedAlertId(alert.id)}
                        className={`rounded-2xl text-slate-200 transition duration-150 cursor-pointer ${
                          selectedAlertId === alert.id || (!selectedAlertId && selectedAlert?.id === alert.id)
                            ? "bg-white/15 ring-1 ring-cyan/40"
                            : "bg-white/5 hover:bg-white/10"
                        }`}
                      >
                        {/* Severity Badge */}
                        <td className="rounded-l-2xl px-4 py-3">
                          <span
                            className="rounded-full px-2.5 py-0.5 text-xs font-mono font-bold"
                            style={{
                              backgroundColor: `${severityColors[alert.severity]}18`,
                              color: severityColors[alert.severity] || "#cbd5e1"
                            }}
                          >
                            {alert.severity}
                          </span>
                        </td>
                        
                        {/* Incident Classification */}
                        <td className="px-4 py-3 font-semibold text-white max-w-[200px] truncate">
                          {alert.attack_type}
                        </td>
                        
                        {/* Source IP address */}
                        <td className="px-4 py-3 font-mono font-medium text-cyan">
                          {alert.source_ip}
                        </td>
                        
                        {/* Log Source Name */}
                        <td className="px-4 py-3 font-mono text-xs text-slate-400">
                          {sourceNames[alert.source] || alert.source}
                        </td>
                        
                        {/* Correlated Score */}
                        <td className="px-4 py-3 font-mono font-bold">
                          {alert.l1_score}
                        </td>
                        
                        {/* Resolution Status Badge */}
                        <td className="px-4 py-3">
                          <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full font-bold uppercase tracking-wider ${
                            alert.status === "resolved" ? "bg-lime/15 text-lime border border-lime/25" :
                            alert.status === "escalated" ? "bg-rose-500/15 text-rose-400 border border-rose-500/25" :
                            "bg-yellow-400/10 text-yellow-400 border border-yellow-400/20"
                          }`}>
                            {alert.status}
                          </span>
                        </td>

                        {/* Direct Triage action button */}
                        <td className="rounded-r-2xl px-4 py-3">
                          {alert.status !== "resolved" ? (
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                handleResolveAlert(alert.id);
                              }}
                              className="rounded bg-lime text-slate-950 font-bold px-2.5 py-1 text-[10px] hover:bg-lime/90 transition shadow shadow-lime/10"
                            >
                              Resolve
                            </button>
                          ) : (
                            <span className="text-slate-500 text-xs font-mono">MITIGATED</span>
                          )}
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan="7" className="text-center py-10 text-slate-400">
                        No logs match active filters.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </Panel>

        </section>
      </div>
    </main>
  );
}

function Stat({ label, value }) {
  return (
    <div className="rounded-xl border border-white/5 bg-slate-900/60 p-3">
      <p className="text-[10px] font-mono uppercase tracking-[0.24em] text-slate-500">{label}</p>
      <p className="mt-1.5 text-sm font-semibold text-white font-mono">{value ?? "N/A"}</p>
    </div>
  );
}

export default App;
