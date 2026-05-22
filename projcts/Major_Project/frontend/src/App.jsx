import { useEffect, useMemo, useState } from "react";
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
  Scatter,
  ScatterChart,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { MetricCard } from "./components/MetricCard";
import { Panel } from "./components/Panel";

const API_BASE_URL = "http://127.0.0.1:8000/api";
const severityColors = {
  CRITICAL: "#fb7185",
  HIGH: "#f97316",
  MEDIUM: "#facc15",
  LOW: "#22c55e",
  INFO: "#38bdf8",
  UNKNOWN: "#94a3b8",
};
const pageMetadata = {
  l1: {
    title: "L1 Agent Results",
    description: "High-speed flagging from the L1 SOC filter for fast triage and prioritization.",
  },
  l2: {
    title: "L2 Agent Analysis",
    description: "Local LLM-backed analysis for suspicious flows and attack classification.",
  },
  l3: {
    title: "L3 Final Review",
    description: "LSTM-based sequence review that finds patterns across the L2 output and generates the final verdict.",
  },
};

const chartPalette = ["#3dd9d6", "#a3e635", "#fb7185", "#38bdf8", "#f59e0b", "#c084fc"];

function formatNumber(value) {
  if (value === null || value === undefined || Number.isNaN(value)) {
    return "N/A";
  }
  return Intl.NumberFormat("en-US", { maximumFractionDigits: 1 }).format(value);
}

function buildQuery(filters) {
  const params = new URLSearchParams();
  filters.severity.forEach((value) => params.append("severity", value));
  filters.attackType.forEach((value) => params.append("attackType", value));
  filters.protocol.forEach((value) => params.append("protocol", value));
  params.set("riskMin", String(filters.risk[0]));
  params.set("riskMax", String(filters.risk[1]));
  params.set("confidenceMin", String(filters.confidence[0]));
  params.set("confidenceMax", String(filters.confidence[1]));
  params.set("search", filters.search);
  params.set("onlyHigh", String(filters.onlyHigh));
  return params.toString();
}

function summarizeTrend(alerts) {
  const buckets = new Map();
  alerts
    .filter((alert) => alert.timestamp)
    .forEach((alert) => {
      const key = new Date(alert.timestamp).toLocaleString("en-US", {
        month: "short",
        day: "numeric",
        hour: "2-digit",
      });
      const current = buckets.get(key) ?? { time: key, risk: 0, confidence: 0, count: 0 };
      current.risk += alert.riskScore ?? 0;
      current.confidence += alert.confidence ?? 0;
      current.count += 1;
      buckets.set(key, current);
    });

  return [...buckets.values()].map((item) => ({
    time: item.time,
    risk: item.count ? Number((item.risk / item.count).toFixed(1)) : 0,
    confidence: item.count ? Number((item.confidence / item.count).toFixed(1)) : 0,
  }));
}

function App() {
  const [currentPage, setCurrentPage] = useState("l2");
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [filters, setFilters] = useState({
    severity: [],
    attackType: [],
    protocol: [],
    risk: [0, 100],
    confidence: [0, 100],
    search: "",
    onlyHigh: false,
  });

  useEffect(() => {
    setData(null);
    setError("");
    setFilters({
      severity: [],
      attackType: [],
      protocol: [],
      risk: [0, 100],
      confidence: [0, 100],
      search: "",
      onlyHigh: false,
    });
  }, [currentPage]);

  useEffect(() => {
    let cancelled = false;

    async function loadAlerts() {
      setLoading(true);
      setError("");

      try {
        const response = await fetch(`${API_BASE_URL}/${currentPage}?${buildQuery(filters)}`);
        if (!response.ok) {
          throw new Error(`API request failed with ${response.status}`);
        }
        const payload = await response.json();
        if (cancelled) {
          return;
        }
        setData(payload);
        setFilters((current) => ({
          ...current,
          severity: current.severity.length ? current.severity : payload.filters.severity,
          attackType: current.attackType.length ? current.attackType : payload.filters.attackType,
          protocol: current.protocol.length ? current.protocol : payload.filters.protocol,
        }));
      } catch (fetchError) {
        if (!cancelled) {
          setError(fetchError.message || "Failed to load alert data.");
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }

    loadAlerts();
    return () => {
      cancelled = true;
    };
  }, [currentPage, filters.risk, filters.confidence, filters.search, filters.onlyHigh, filters.severity, filters.attackType, filters.protocol]);

  const alerts = data?.alerts ?? [];
  const summary = data?.summary;
  const datasetSummary = data?.datasetSummary;
  const trendData = useMemo(() => summarizeTrend(alerts).slice(-12), [alerts]);
  const selectedAlert = alerts[0];
  const isL3Page = currentPage === "l3";

  function toggleMultiSelect(key, value) {
    setFilters((current) => {
      const next = current[key].includes(value)
        ? current[key].filter((item) => item !== value)
        : [...current[key], value];
      return { ...current, [key]: next };
    });
  }

  if (loading && !data) {
    return <div className="min-h-screen bg-slate-950 text-slate-100 p-8">Loading dashboard...</div>;
  }

  if (error && !data) {
    return (
      <div className="min-h-screen bg-slate-950 text-slate-100 p-8">
        <div className="glass-panel max-w-2xl p-6">
          <h1 className="font-display text-3xl">SOC AI Dashboard</h1>
          <p className="mt-4 text-rose-300">{error}</p>
          <p className="mt-2 text-slate-300">
            Start the API first with <code>python api_server.py</code>, then run the frontend.
          </p>
        </div>
      </div>
    );
  }

  return (
    <main className="grid-pattern min-h-screen text-slate-100">
      <div className="mx-auto flex w-full max-w-[1600px] gap-6 px-4 py-6 lg:px-6">
        <aside className="glass-panel sticky top-6 hidden h-fit w-[320px] shrink-0 p-5 lg:block">
          <p className="font-display text-2xl">Control Tower</p>
          <p className="mt-2 text-sm text-slate-300">
            Filter the current view while keeping the total dataset context visible.
          </p>

          <div className="mt-6 space-y-6 text-sm">
            <FilterSection
              title="Severity"
              items={data?.filters.severity ?? []}
              activeItems={filters.severity}
              onToggle={(value) => toggleMultiSelect("severity", value)}
            />
            <FilterSection
              title="Attack Type"
              items={data?.filters.attackType ?? []}
              activeItems={filters.attackType}
              onToggle={(value) => toggleMultiSelect("attackType", value)}
            />
            <FilterSection
              title="Protocol"
              items={data?.filters.protocol ?? []}
              activeItems={filters.protocol}
              onToggle={(value) => toggleMultiSelect("protocol", value)}
            />

            <RangeControl
              label="Risk Score"
              value={filters.risk}
              min={0}
              max={100}
              onChange={(next) => setFilters((current) => ({ ...current, risk: next }))}
            />

            <RangeControl
              label="Confidence"
              value={filters.confidence}
              min={0}
              max={100}
              onChange={(next) => setFilters((current) => ({ ...current, confidence: next }))}
            />

            <div>
              <label className="mb-2 block text-slate-300">Search</label>
              <input
                className="w-full rounded-2xl border border-white/10 bg-white/5 px-4 py-3 text-sm text-white outline-none transition focus:border-cyan/80"
                placeholder="IP, port, flow, attack..."
                value={filters.search}
                onChange={(event) => setFilters((current) => ({ ...current, search: event.target.value }))}
              />
            </div>

            <label className="flex items-center gap-3 rounded-2xl border border-white/10 bg-white/5 px-4 py-3">
              <input
                type="checkbox"
                checked={filters.onlyHigh}
                onChange={(event) => setFilters((current) => ({ ...current, onlyHigh: event.target.checked }))}
              />
              <span>Only high-priority alerts</span>
            </label>
          </div>
        </aside>

        <section className="min-w-0 flex-1">
          <div className="mb-6 flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
            <div>
              <div className="mb-4 flex flex-wrap gap-3">
                {Object.entries(pageMetadata).map(([key, page]) => (
                  <button
                    key={key}
                    type="button"
                    onClick={() => setCurrentPage(key)}
                    className={`rounded-full px-4 py-2 text-sm font-semibold transition ${
                      currentPage === key
                        ? "bg-cyan text-slate-950 shadow-lg shadow-cyan/20"
                        : "border border-white/10 bg-white/5 text-slate-100 hover:border-white/20"
                    }`}
                  >
                    {page.title}
                  </button>
                ))}
              </div>
              <p className="font-display text-4xl tracking-tight">{pageMetadata[currentPage]?.title ?? "SOC AI Dashboard"}</p>
              <p className="mt-2 max-w-3xl text-slate-300">{pageMetadata[currentPage]?.description}</p>
            </div>
            <div className="glass-panel px-5 py-4 text-sm text-slate-300">
              <p>Dataset size: <span className="font-semibold text-white">{datasetSummary?.totalAlerts ?? 0}</span></p>
              <p className="mt-1">
                Showing <span className="font-semibold text-cyan">{summary?.totalAlerts ?? 0}</span> alerts in the current view
              </p>
            </div>
          </div>

          <div className={`grid gap-4 md:grid-cols-2 ${isL3Page ? "xl:grid-cols-6" : "xl:grid-cols-5"}`}>
            <MetricCard title="Total Dataset" value={datasetSummary?.totalAlerts} accent="cyan" subtitle="Complete alert population" />
            <MetricCard title="Filtered Alerts" value={summary?.totalAlerts} accent="lime" subtitle={`of ${datasetSummary?.totalAlerts ?? 0} total`} />
            <MetricCard title="High Risk" value={summary?.highRiskAlerts} accent="ember" subtitle={`of ${datasetSummary?.highRiskAlerts ?? 0} total`} />
            <MetricCard title="Avg Risk" value={formatNumber(summary?.averageRisk)} accent="cyan" subtitle="Current filtered view" />
            <MetricCard title="Avg Confidence" value={formatNumber(summary?.averageConfidence)} accent="lime" subtitle="Current filtered view" />
            {isL3Page ? <MetricCard title="Avg Pattern Score" value={formatNumber(summary?.averagePatternScore)} accent="ember" subtitle="LSTM reconstruction signal" /> : null}
          </div>

          <div className="mt-6 grid gap-6 xl:grid-cols-[1.5fr_1fr]">
            <Panel title="Risk and Confidence Trend" subtitle="Recent average values across the filtered alerts">
              <div className="h-80">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={trendData}>
                    <defs>
                      <linearGradient id="riskFill" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#3dd9d6" stopOpacity={0.7} />
                        <stop offset="95%" stopColor="#3dd9d6" stopOpacity={0} />
                      </linearGradient>
                      <linearGradient id="confidenceFill" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#a3e635" stopOpacity={0.5} />
                        <stop offset="95%" stopColor="#a3e635" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid stroke="rgba(255,255,255,0.08)" vertical={false} />
                    <XAxis dataKey="time" stroke="#cbd5e1" tickLine={false} axisLine={false} />
                    <YAxis stroke="#cbd5e1" tickLine={false} axisLine={false} />
                    <Tooltip />
                    <Area type="monotone" dataKey="risk" stroke="#3dd9d6" fill="url(#riskFill)" strokeWidth={2} />
                    <Area type="monotone" dataKey="confidence" stroke="#a3e635" fill="url(#confidenceFill)" strokeWidth={2} />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </Panel>

            <Panel title="Severity Mix" subtitle="Current filtered view">
              <div className="h-80">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={Object.entries(summary?.severityBreakdown ?? {}).map(([name, value]) => ({ name, value }))}
                      dataKey="value"
                      nameKey="name"
                      innerRadius={70}
                      outerRadius={108}
                      paddingAngle={2}
                    >
                      {Object.keys(summary?.severityBreakdown ?? {}).map((severity) => (
                        <Cell key={severity} fill={severityColors[severity] ?? "#94a3b8"} />
                      ))}
                    </Pie>
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </Panel>
          </div>

          <div className="mt-6 grid gap-6 xl:grid-cols-3">
            <Panel title="Attack Types">
              <MiniBarChart data={summary?.attackTypeBreakdown ?? []} color="#3dd9d6" />
            </Panel>
            <Panel title="Top Source IPs">
              <MiniBarChart data={summary?.topSourceIps ?? []} color="#a3e635" />
            </Panel>
            <Panel title="Destination Ports">
              <MiniBarChart data={summary?.topDestinationPorts ?? []} color="#fb7185" />
            </Panel>
          </div>

          <div className="mt-6 grid gap-6 xl:grid-cols-[1.25fr_1fr]">
            <Panel title="Traffic Pattern Map" subtitle="Packets/sec vs Bytes/sec">
              <div className="h-96">
                <ResponsiveContainer width="100%" height="100%">
                  <ScatterChart>
                    <CartesianGrid stroke="rgba(255,255,255,0.08)" />
                    <XAxis type="number" dataKey="flowPacketsPerSec" name="Packets/s" stroke="#cbd5e1" />
                    <YAxis type="number" dataKey="flowBytesPerSec" name="Bytes/s" stroke="#cbd5e1" />
                    <Tooltip cursor={{ strokeDasharray: "3 3" }} />
                    <Scatter data={alerts.slice(0, 80)} fill="#3dd9d6" />
                  </ScatterChart>
                </ResponsiveContainer>
              </div>
            </Panel>

            <Panel title={isL3Page ? "Final Review" : "Priority Alert"} subtitle={isL3Page ? "LSTM-based verdict for the top reviewed sequence" : "Top-ranked alert in the filtered set"}>
              {selectedAlert ? (
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <span
                      className="rounded-full px-3 py-1 text-xs font-semibold uppercase tracking-[0.24em]"
                      style={{ backgroundColor: `${severityColors[selectedAlert.severity] ?? "#94a3b8"}22`, color: severityColors[selectedAlert.severity] ?? "#94a3b8" }}
                    >
                      {selectedAlert.severity}
                    </span>
                    <span className="text-sm text-slate-300">Risk {selectedAlert.riskScore ?? "N/A"}</span>
                  </div>
                  <div>
                    <p className="font-display text-2xl">{selectedAlert.attackType}</p>
                    <p className="mt-1 text-sm text-slate-300">
                      {selectedAlert.srcIp}:{selectedAlert.srcPort} to {selectedAlert.dstIp}:{selectedAlert.dstPort}
                    </p>
                  </div>
                  {isL3Page ? (
                    <div className="rounded-2xl border border-cyan/20 bg-cyan/10 p-4">
                      <p className="text-xs uppercase tracking-[0.24em] text-cyan-200">L3 Final Review</p>
                      <p className="mt-2 text-sm leading-6 text-slate-100">{selectedAlert.finalReview ?? selectedAlert.explanation}</p>
                    </div>
                  ) : null}
                  <div className="rounded-2xl border border-white/10 bg-white/5 p-4">
                    <p className="text-xs uppercase tracking-[0.24em] text-slate-400">Explanation</p>
                    <p className="mt-2 text-sm leading-6 text-slate-200">{selectedAlert.explanation}</p>
                  </div>
                  <div className="rounded-2xl border border-lime/20 bg-lime/10 p-4">
                    <p className="text-xs uppercase tracking-[0.24em] text-lime-200">Recommendation</p>
                    <p className="mt-2 text-sm leading-6 text-slate-100">{selectedAlert.recommendation}</p>
                  </div>
                  <div className="grid grid-cols-2 gap-3 text-sm">
                    <Stat label="Protocol" value={selectedAlert.protocolName} />
                    <Stat label="Confidence" value={selectedAlert.confidence} />
                    <Stat label="Flow Bytes/s" value={formatNumber(selectedAlert.flowBytesPerSec)} />
                    <Stat label="Flow Packets/s" value={formatNumber(selectedAlert.flowPacketsPerSec)} />
                    {isL3Page ? <Stat label="Pattern Score" value={formatNumber(selectedAlert.patternScore)} /> : null}
                  </div>
                </div>
              ) : (
                <p className="text-slate-300">No alert available for the current filters.</p>
              )}
            </Panel>
          </div>

          <Panel title="Alert Queue" subtitle="Top 12 alerts sorted by risk and confidence" className="mt-6">
            <div className="overflow-x-auto">
              <table className="min-w-full border-separate border-spacing-y-2 text-left text-sm">
                <thead className="text-slate-400">
                  <tr>
                    <th className="px-3 py-2 font-medium">Severity</th>
                    <th className="px-3 py-2 font-medium">Attack</th>
                    <th className="px-3 py-2 font-medium">Source</th>
                    <th className="px-3 py-2 font-medium">Destination</th>
                    <th className="px-3 py-2 font-medium">Risk</th>
                    <th className="px-3 py-2 font-medium">Confidence</th>
                    <th className="px-3 py-2 font-medium">Protocol</th>
                  </tr>
                </thead>
                <tbody>
                  {alerts.slice(0, 12).map((alert) => (
                    <tr key={`${alert.flowId}-${alert.timestamp}`} className="rounded-2xl bg-white/5 text-slate-200">
                      <td className="rounded-l-2xl px-3 py-3">
                        <span
                          className="rounded-full px-3 py-1 text-xs font-semibold"
                          style={{ backgroundColor: `${severityColors[alert.severity] ?? "#94a3b8"}22`, color: severityColors[alert.severity] ?? "#94a3b8" }}
                        >
                          {alert.severity}
                        </span>
                      </td>
                      <td className="px-3 py-3">{alert.attackType}</td>
                      <td className="px-3 py-3">{alert.srcIp}:{alert.srcPort}</td>
                      <td className="px-3 py-3">{alert.dstIp}:{alert.dstPort}</td>
                      <td className="px-3 py-3">{formatNumber(alert.riskScore)}</td>
                      <td className="px-3 py-3">{formatNumber(alert.confidence)}</td>
                      <td className="rounded-r-2xl px-3 py-3">{alert.protocolName}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Panel>
        </section>
      </div>
    </main>
  );
}

function FilterSection({ title, items, activeItems, onToggle }) {
  return (
    <div>
      <p className="mb-3 text-slate-300">{title}</p>
      <div className="flex flex-wrap gap-2">
        {items.map((item) => {
          const active = activeItems.includes(item);
          return (
            <button
              key={item}
              type="button"
              onClick={() => onToggle(item)}
              className={`rounded-full border px-3 py-2 transition ${
                active
                  ? "border-cyan bg-cyan/15 text-cyan"
                  : "border-white/10 bg-white/5 text-slate-300 hover:border-white/30"
              }`}
            >
              {item}
            </button>
          );
        })}
      </div>
    </div>
  );
}

function RangeControl({ label, value, min, max, onChange }) {
  return (
    <div>
      <div className="mb-2 flex items-center justify-between text-slate-300">
        <span>{label}</span>
        <span className="text-white">
          {value[0]} - {value[1]}
        </span>
      </div>
      <div className="grid gap-3">
        <input
          type="range"
          min={min}
          max={max}
          value={value[0]}
          onChange={(event) => onChange([Math.min(Number(event.target.value), value[1]), value[1]])}
        />
        <input
          type="range"
          min={min}
          max={max}
          value={value[1]}
          onChange={(event) => onChange([value[0], Math.max(Number(event.target.value), value[0])])}
        />
      </div>
    </div>
  );
}

function MiniBarChart({ data, color }) {
  return (
    <div className="h-72">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} layout="vertical" margin={{ top: 8, right: 12, bottom: 8, left: 12 }}>
          <CartesianGrid stroke="rgba(255,255,255,0.08)" horizontal={false} />
          <XAxis type="number" stroke="#cbd5e1" axisLine={false} tickLine={false} />
          <YAxis type="category" dataKey="label" width={110} stroke="#cbd5e1" axisLine={false} tickLine={false} />
          <Tooltip />
          <Bar dataKey="value" fill={color} radius={[0, 14, 14, 0]}>
            {data.map((entry, index) => (
              <Cell key={`${entry.label}-${index}`} fill={chartPalette[index % chartPalette.length]} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

function Stat({ label, value }) {
  return (
    <div className="rounded-2xl border border-white/10 bg-white/5 p-3">
      <p className="text-xs uppercase tracking-[0.24em] text-slate-400">{label}</p>
      <p className="mt-2 text-base font-medium text-white">{value ?? "N/A"}</p>
    </div>
  );
}

export default App;
