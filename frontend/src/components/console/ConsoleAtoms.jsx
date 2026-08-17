import { statusMeta, severityMeta } from "../../data/scans";

const colorClasses = {
  signal: "text-signal border-signal/40 bg-signal/10",
  amber: "text-amber border-amber/40 bg-amber/10",
  red: "text-red border-red/40 bg-red/10",
  steel: "text-steel border-steel/40 bg-steel/10",
  ink: "text-ink-3 border-line bg-panel-2",
};

export function StatusPill({ status }) {
  const meta = statusMeta[status] ?? statusMeta.queued;
  const c = colorClasses[meta.color];
  return (
    <span className={`inline-flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-widest px-2 py-1 border ${c}`}>
      <span className="w-1.5 h-1.5 rounded-full bg-current" />
      {meta.label}
    </span>
  );
}

export function SeverityPill({ severity }) {
  const meta = severityMeta[severity] ?? severityMeta.low;
  const c = colorClasses[meta.color];
  return (
    <span className={`inline-flex items-center font-mono text-[10px] uppercase tracking-widest px-2 py-1 border ${c}`}>
      {meta.label}
    </span>
  );
}

export function StatCard({ label, value, sub, accent = "ink" }) {
  const textColor = {
    signal: "text-signal",
    amber: "text-amber",
    red: "text-red",
    steel: "text-steel",
    ink: "text-ink-1",
  }[accent];
  return (
    <div className="bg-panel-2 border border-line p-5">
      <p className="font-mono text-[10px] uppercase tracking-widest text-ink-3">{label}</p>
      <p className={`mt-2 font-display text-3xl ${textColor}`}>{value}</p>
      {sub && <p className="mt-1 text-xs text-ink-3">{sub}</p>}
    </div>
  );
}

export function Panel({ title, action, children, className = "" }) {
  return (
    <div className={`bg-panel-2 border border-line ${className}`}>
      {(title || action) && (
        <div className="flex items-center justify-between px-5 py-3.5 border-b border-line">
          {title && (
            <h3 className="font-mono text-[11px] uppercase tracking-widest text-ink-1">{title}</h3>
          )}
          {action}
        </div>
      )}
      <div className="p-5">{children}</div>
    </div>
  );
}
