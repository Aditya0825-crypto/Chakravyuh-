export default function Footer() {
  return (
    <footer className="relative border-t border-line px-6 md:px-10 py-10">
      <div className="mx-auto max-w-[1400px] flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div className="flex items-center gap-2.5">
          <span className="relative w-4 h-4 flex items-center justify-center">
            <span className="absolute inset-0 rounded-full border border-signal/70" />
            <span className="w-1 h-1 rounded-full bg-signal" />
          </span>
          <span className="font-mono text-xs text-ink-3 tracking-wide">
            CHAKRAVYUH v4.1 — Prototype built for AI Kavach 2026
          </span>
        </div>
        <span className="font-mono text-[11px] text-ink-3 uppercase tracking-[0.2em]">
          Human-Gated · Open-Source · Air-Gap Capable
        </span>
      </div>
    </footer>
  );
}
