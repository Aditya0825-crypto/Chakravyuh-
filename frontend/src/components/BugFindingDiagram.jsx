import { motion } from "framer-motion";
import { bugFindingMethods } from "../data/stages";

export default function BugFindingDiagram() {
  return (
    <div className="relative mt-8 py-6">
      <div className="grid md:grid-cols-[1fr_auto_1fr] gap-6 items-center">
        <div className="grid gap-3">
          {bugFindingMethods.map((m, i) => (
            <motion.div
              key={m.id}
              initial={{ opacity: 0, x: -16 }}
              whileInView={{ opacity: 1, x: 0 }}
              viewport={{ once: true, amount: 0.6 }}
              transition={{ duration: 0.45, delay: i * 0.1 }}
              className="relative bg-panel-2 border border-line px-4 py-3 clip-corner"
            >
              <div className="flex items-center justify-between">
                <span className="font-mono text-xs uppercase tracking-widest text-steel">{m.label}</span>
                <span className="font-mono text-[10px] text-ink-3">{m.tool}</span>
              </div>
              <p className="mt-1.5 text-sm text-ink-2">{m.desc}</p>
            </motion.div>
          ))}
        </div>

        <div className="relative h-32 md:h-full flex items-center justify-center">
          <svg
            viewBox="0 0 120 160"
            className="w-16 md:w-20 h-full text-line rotate-90 md:rotate-0"
            aria-hidden="true"
          >
            <path d="M5 20 L60 80 L5 140" fill="none" stroke="currentColor" strokeWidth="1.5" />
            <path d="M60 80 L115 80" fill="none" stroke="currentColor" strokeWidth="1.5" />
            {[20, 80, 140].map((y, i) => (
              <motion.circle
                key={y}
                cx="5"
                cy={y}
                r="3"
                fill="#00ff9d"
                initial={{ opacity: 0.15 }}
                whileInView={{ opacity: [0.15, 1, 0.15] }}
                viewport={{ once: false, amount: 0.6 }}
                transition={{ duration: 1.6, delay: i * 0.25, repeat: Infinity, repeatDelay: 1.2 }}
              />
            ))}
            <motion.circle
              cx="115"
              cy="80"
              r="4"
              fill="#00ff9d"
              initial={{ opacity: 0.3 }}
              whileInView={{ opacity: [0.3, 1, 0.3] }}
              viewport={{ once: false, amount: 0.6 }}
              transition={{ duration: 1.4, repeat: Infinity }}
            />
          </svg>
        </div>

        <motion.div
          initial={{ opacity: 0, x: 16 }}
          whileInView={{ opacity: 1, x: 0 }}
          viewport={{ once: true, amount: 0.6 }}
          transition={{ duration: 0.45, delay: 0.3 }}
          className="bg-panel-3 border border-signal/30 px-5 py-5 clip-corner"
        >
          <span className="font-mono text-xs uppercase tracking-widest text-signal">
            Reasoning Orchestrator
          </span>
          <p className="mt-2 text-sm text-ink-2 leading-relaxed">
            Cross-checks and deduplicates findings from all three methods before anything
            is admitted as a candidate bug.
          </p>
        </motion.div>
      </div>
    </div>
  );
}
