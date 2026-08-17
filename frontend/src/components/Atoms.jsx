export function Eyebrow({ children, accent = "signal" }) {
  const colorMap = {
    signal: "text-signal border-signal/40",
    amber: "text-amber border-amber/40",
    red: "text-red border-red/40",
    steel: "text-steel border-steel/40",
  };
  return (
    <span
      className={`inline-flex items-center gap-2 font-mono text-[11px] uppercase tracking-[0.28em] border px-3 py-1 ${colorMap[accent]}`}
    >
      <span className="w-1.5 h-1.5 bg-current animate-pulse-slow" />
      {children}
    </span>
  );
}

export function Chip({ children }) {
  return (
    <span className="font-mono text-[11px] tracking-wide uppercase text-ink-2 border border-line px-2.5 py-1 bg-panel-1/60">
      {children}
    </span>
  );
}

export function SectionHeading({ eyebrow, accent, title, sub }) {
  return (
    <div className="max-w-3xl">
      {eyebrow && <Eyebrow accent={accent}>{eyebrow}</Eyebrow>}
      <h2 className="mt-5 font-display text-4xl md:text-5xl font-medium tracking-tight text-ink-1">
        {title}
      </h2>
      {sub && <p className="mt-4 text-ink-2 text-lg leading-relaxed">{sub}</p>}
    </div>
  );
}
