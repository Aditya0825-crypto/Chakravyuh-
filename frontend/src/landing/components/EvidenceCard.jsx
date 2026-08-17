import { motion } from "framer-motion";
import { evidenceCard } from "../data/stages";

export default function EvidenceCard() {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, amount: 0.4 }}
      transition={{ duration: 0.55 }}
      className="mt-8 bg-panel-1 border border-signal/25 clip-corner overflow-hidden"
    >
      <div className="flex items-center justify-between px-5 py-3 border-b border-line bg-panel-2">
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-red/70" />
          <span className="w-2 h-2 rounded-full bg-amber/70" />
          <span className="w-2 h-2 rounded-full bg-signal/70" />
          <span className="font-mono text-[11px] text-ink-3 ml-2 uppercase tracking-widest">
            vulndna_match.evidence
          </span>
        </div>
        <span className="font-mono text-[10px] text-ink-3 uppercase tracking-widest">
          confidence: {evidenceCard.confidence}
        </span>
      </div>

      <div className="p-5 md:p-6 grid md:grid-cols-[1fr_auto] gap-6">
        <div>
          <div className="flex flex-wrap items-center gap-3">
            <span className="font-mono text-signal text-sm">{evidenceCard.cveId}</span>
            <span className="text-ink-3 text-xs">·</span>
            <span className="text-ink-1 text-sm">{evidenceCard.title}</span>
          </div>

          <pre className="mt-4 bg-void border border-line px-4 py-3 text-[12px] leading-relaxed font-mono text-ink-2 overflow-x-auto">
            <code>{evidenceCard.snippet}</code>
          </pre>

          <div className="mt-4 flex items-start gap-2 text-sm">
            <span className="font-mono text-[11px] uppercase tracking-widest text-ink-3 mt-0.5">
              Fix pattern
            </span>
            <span className="text-ink-2">{evidenceCard.fixPattern}</span>
          </div>
        </div>

        <div className="flex md:flex-col items-center md:items-end justify-between md:justify-start gap-2">
          <span className="font-mono text-[10px] uppercase tracking-widest text-ink-3">
            Similarity
          </span>
          <div className="relative w-20 h-20">
            <svg viewBox="0 0 36 36" className="w-full h-full -rotate-90">
              <circle cx="18" cy="18" r="15.5" fill="none" stroke="#1a2521" strokeWidth="3" />
              <motion.circle
                cx="18"
                cy="18"
                r="15.5"
                fill="none"
                stroke="#00ff9d"
                strokeWidth="3"
                strokeLinecap="round"
                strokeDasharray={2 * Math.PI * 15.5}
                initial={{ strokeDashoffset: 2 * Math.PI * 15.5 }}
                whileInView={{
                  strokeDashoffset: 2 * Math.PI * 15.5 * (1 - evidenceCard.similarity / 100),
                }}
                viewport={{ once: true, amount: 0.5 }}
                transition={{ duration: 1.1, ease: "easeOut" }}
              />
            </svg>
            <span className="absolute inset-0 flex items-center justify-center font-mono text-sm text-ink-1">
              {evidenceCard.similarity}%
            </span>
          </div>
        </div>
      </div>
    </motion.div>
  );
}
