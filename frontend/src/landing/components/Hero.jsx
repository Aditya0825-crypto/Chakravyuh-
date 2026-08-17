import { motion } from "framer-motion";
import { ChevronDown, ShieldHalf } from "lucide-react";

export default function Hero() {
  return (
    <section id="top" className="relative min-h-[100svh] flex flex-col justify-center px-6 md:px-10 pt-16">
      <div className="mx-auto max-w-[1400px] w-full">
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          className="flex items-center gap-3 mb-10"
        >
          <span className="inline-flex items-center gap-2 font-mono text-[11px] uppercase tracking-[0.28em] text-amber border border-amber/40 px-3 py-1.5">
            <ShieldHalf size={12} strokeWidth={2.5} />
            AI Kavach 2026 — Defense Prototype
          </span>
        </motion.div>

        <div className="flex flex-col sm:flex-row items-start gap-2 sm:gap-5 md:gap-8">
          <motion.span
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.8, delay: 0.15 }}
            className="font-display text-2xl md:text-5xl text-signal/80 sm:pt-2 md:pt-4 shrink-0 select-none"
            lang="hi"
          >
            चक्रव्यूह
          </motion.span>
          <motion.h1
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.7, delay: 0.05 }}
            className="font-display font-medium tracking-tight text-[13vw] leading-[0.92] sm:text-[14vw] md:text-[7.4vw] text-ink-1 max-w-full"
          >
            CHAKRAVYUH
          </motion.h1>
        </div>

        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.3 }}
          className="mt-8 max-w-2xl border-l-2 border-signal/50 pl-5"
        >
          <p className="font-mono text-signal text-sm uppercase tracking-[0.2em] mb-3">
            Autonomous Cyber Reasoning System
          </p>
          <p className="text-ink-2 text-lg md:text-xl leading-relaxed">
            Chakravyuh finds real vulnerabilities, proves they're exploitable, and proposes
            evidence-backed patches — then stops, every time, for a human to decide.
          </p>
        </motion.div>

        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.6, delay: 0.55 }}
          className="mt-14 flex flex-wrap gap-x-10 gap-y-4 font-mono text-xs text-ink-3 uppercase tracking-[0.16em]"
        >
          <span>6-Stage Pipeline</span>
          <span className="text-line">/</span>
          <span>8GB VRAM Footprint</span>
          <span className="text-line">/</span>
          <span>Zero Cloud Dependency</span>
          <span className="text-line">/</span>
          <span>Human Safety Gate</span>
        </motion.div>
      </div>

      <motion.a
        href="#problem"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 0.6, delay: 0.9 }}
        className="absolute bottom-8 left-1/2 -translate-x-1/2 flex flex-col items-center gap-2 text-ink-3 hover:text-signal transition-colors"
        aria-label="Scroll to next section"
      >
        <span className="font-mono text-[10px] uppercase tracking-[0.3em]">Scroll</span>
        <motion.span
          animate={{ y: [0, 6, 0] }}
          transition={{ repeat: Infinity, duration: 1.8, ease: "easeInOut" }}
        >
          <ChevronDown size={16} />
        </motion.span>
      </motion.a>
    </section>
  );
}
