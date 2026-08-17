import { motion } from "framer-motion";
import { ShieldCheck, Lock } from "lucide-react";
import { gateStates } from "../data/stages";

const colorMap = {
  signal: { text: "text-signal", border: "border-signal/50", bg: "bg-signal/10" },
  amber: { text: "text-amber", border: "border-amber/50", bg: "bg-amber/10" },
  red: { text: "text-red", border: "border-red/50", bg: "bg-red/10" },
};

export default function HumanGatePanel() {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, amount: 0.4 }}
      transition={{ duration: 0.55 }}
      className="mt-8 border border-ink-3/40 bg-panel-1 relative"
    >
      <div className="absolute -top-px -left-px w-4 h-4 border-t border-l border-ink-1/70" />
      <div className="absolute -top-px -right-px w-4 h-4 border-t border-r border-ink-1/70" />
      <div className="absolute -bottom-px -left-px w-4 h-4 border-b border-l border-ink-1/70" />
      <div className="absolute -bottom-px -right-px w-4 h-4 border-b border-r border-ink-1/70" />

      <div className="flex items-center justify-between px-6 py-4 border-b border-line">
        <div className="flex items-center gap-2.5">
          <Lock size={14} className="text-ink-1" strokeWidth={2.5} />
          <span className="font-mono text-[11px] uppercase tracking-[0.24em] text-ink-1">
            Human Decision Required
          </span>
        </div>
        <span className="font-mono text-[10px] uppercase tracking-[0.2em] text-ink-3">
          No autonomous deploy
        </span>
      </div>

      <div className="p-6 grid md:grid-cols-3 gap-4">
        {gateStates.map((g, i) => {
          const c = colorMap[g.color];
          return (
            <motion.div
              key={g.id}
              initial={{ opacity: 0, y: 12 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, amount: 0.5 }}
              transition={{ duration: 0.4, delay: i * 0.08 }}
              className={`border ${c.border} ${c.bg} px-4 py-4`}
            >
              <span className={`font-mono text-sm tracking-widest ${c.text}`}>{g.label}</span>
              <p className="mt-2 text-sm text-ink-2 leading-relaxed">{g.desc}</p>
            </motion.div>
          );
        })}
      </div>

      <div className="px-6 pb-6 flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
        <div className="flex-1 flex items-center gap-2 text-ink-2 text-sm">
          <ShieldCheck size={16} className="text-signal shrink-0" />
          Every recommendation carries evidence, root cause, and test results — the human sees the full trail.
        </div>
        <div className="flex gap-2 shrink-0">
          <button className="font-mono text-[11px] uppercase tracking-widest px-4 py-2.5 border border-signal/50 text-signal hover:bg-signal/10 transition-colors">
            Approve
          </button>
          <button className="font-mono text-[11px] uppercase tracking-widest px-4 py-2.5 border border-red/50 text-red hover:bg-red/10 transition-colors">
            Reject
          </button>
        </div>
      </div>
    </motion.div>
  );
}
