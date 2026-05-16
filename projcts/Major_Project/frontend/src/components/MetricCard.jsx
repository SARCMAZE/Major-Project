export function MetricCard({ title, value, subtitle, accent = "cyan" }) {
  const accents = {
    cyan: "from-cyan/30 to-cyan/5 text-cyan",
    lime: "from-lime/30 to-lime/5 text-lime",
    ember: "from-ember/30 to-ember/5 text-ember",
  };

  return (
    <div className="glass-panel overflow-hidden p-5">
      <div className={`mb-4 h-1.5 rounded-full bg-gradient-to-r ${accents[accent] ?? accents.cyan}`} />
      <p className="text-sm uppercase tracking-[0.24em] text-slate-400">{title}</p>
      <p className="mt-3 font-display text-4xl text-white">{value ?? "N/A"}</p>
      <p className="mt-2 text-sm text-slate-300">{subtitle}</p>
    </div>
  );
}
