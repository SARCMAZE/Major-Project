export function Panel({ title, subtitle, className = "", children }) {
  return (
    <section className={`glass-panel p-5 ${className}`}>
      <div className="mb-5">
        <h2 className="font-display text-2xl text-white">{title}</h2>
        {subtitle ? <p className="mt-1 text-sm text-slate-300">{subtitle}</p> : null}
      </div>
      {children}
    </section>
  );
}
