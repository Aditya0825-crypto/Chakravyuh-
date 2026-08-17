import { motion } from "framer-motion";
import {
  Radar,
  Bug,
  ShieldCheck,
  Dna,
  Wrench,
  UserCheck,
} from "lucide-react";
import { Chip } from "./Atoms";

const icons = {
  recon: Radar,
  bugfinding: Bug,
  verification: ShieldCheck,
  vulndna: Dna,
  patchengine: Wrench,
  reportgate: UserCheck,
};

const accentMap = {
  signal: { text: "text-signal", border: "border-signal/40" },
  amber: { text: "text-amber", border: "border-amber/40" },
  red: { text: "text-red", border: "border-red/40" },
  steel: { text: "text-steel", border: "border-steel/40" },
};

export default function PipelineStage({ stage, children }) {
  const Icon = icons[stage.id];
  const c = accentMap[stage.accent];

  return (
    <div id={stage.id} className="relative py-14 md:py-20 scroll-mt-24">
      <div className="absolute left-[26px] md:left-[38px] top-16 md:top-20 -translate-x-1/2 z-10">
        <span className={`block w-3.5 h-3.5 rounded-full border-2 ${c.border} bg-void`} />
      </div>

      <div className="pl-16 md:pl-24">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 0.3 }}
          transition={{ duration: 0.6 }}
        >
          <div className="flex items-center gap-3">
            <span className={`font-mono text-xs tracking-[0.25em] ${c.text}`}>
              STAGE {stage.number}
            </span>
            <span className="font-mono text-xs text-ink-3">/ 06</span>
            {stage.isHeadline && (
              <span className="font-mono text-[10px] uppercase tracking-widest px-2 py-0.5 border border-signal/50 text-signal">
                Chakravyuh's Key Innovation
              </span>
            )}
            {stage.isGate && (
              <span className="font-mono text-[10px] uppercase tracking-widest px-2 py-0.5 border border-ink-1/40 text-ink-1">
                Always Human-Approved
              </span>
            )}
          </div>

          <div className="mt-4 flex items-center gap-3">
            <span className={`w-10 h-10 flex items-center justify-center border ${c.border} shrink-0`}>
              <Icon size={18} className={c.text} strokeWidth={1.8} />
            </span>
            <h3 className="font-display text-2xl md:text-4xl text-ink-1 tracking-tight">
              {stage.name}
            </h3>
            <span className="font-display text-lg text-ink-3 hidden sm:inline" lang="hi">
              {stage.devanagari}
            </span>
          </div>

          <p className="mt-4 text-ink-2 text-base md:text-lg leading-relaxed max-w-2xl">
            {stage.line}
          </p>
          <p className="mt-3 text-ink-3 text-sm leading-relaxed max-w-2xl">{stage.detail}</p>

          <div className="mt-5 flex flex-wrap gap-2">
            {stage.chips.map((chip) => (
              <Chip key={chip}>{chip}</Chip>
            ))}
          </div>
        </motion.div>

        {children}
      </div>
    </div>
  );
}
