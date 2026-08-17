import { motion } from "framer-motion";
import { SectionHeading } from "./Atoms";
import { judgeCriteria } from "../data/criteria";

export default function JudgeCriteriaGrid() {
  return (
    <section id="criteria" className="relative px-6 md:px-10 py-24 md:py-32">
      <div className="mx-auto max-w-[1400px]">
        <SectionHeading
          eyebrow="Why This Wins"
          accent="amber"
          title="Built against the judging rubric, not around it"
          sub="Every criterion has a proof point in the system itself — not a slide claim."
        />

        <div className="mt-14 grid sm:grid-cols-2 lg:grid-cols-4 gap-px bg-line">
          {judgeCriteria.map((c, i) => (
            <motion.div
              key={c.id}
              initial={{ opacity: 0, y: 18 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, amount: 0.4 }}
              transition={{ duration: 0.45, delay: (i % 4) * 0.08 }}
              className="bg-void p-6 flex flex-col justify-between min-h-[220px] hover:bg-panel-1 transition-colors"
            >
              <div>
                <span className="font-mono text-[10px] uppercase tracking-widest text-ink-3">
                  {String(i + 1).padStart(2, "0")}
                </span>
                <h3 className="mt-2 font-display text-lg text-ink-1">{c.name}</h3>
                <p className="mt-3 text-sm text-ink-2 leading-relaxed">{c.proof}</p>
              </div>
              <span className="mt-5 inline-block font-mono text-xs text-amber tracking-wide border-t border-line pt-3">
                {c.metric}
              </span>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}
