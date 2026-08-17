import { motion } from "framer-motion";
import { Check, X } from "lucide-react";
import { Eyebrow } from "./Atoms";
import { positioning } from "../data/criteria";

export default function ClosingPositioning() {
  return (
    <section className="relative px-6 md:px-10 py-24 md:py-32">
      <div className="mx-auto max-w-[1400px]">
        <Eyebrow accent="steel">Positioning</Eyebrow>
        <h2 className="mt-5 font-display text-3xl md:text-5xl font-medium tracking-tight text-ink-1 max-w-2xl">
          Honest about what it is. Honest about what it isn't.
        </h2>

        <div className="mt-14 grid md:grid-cols-2 gap-px bg-line">
          <motion.div
            initial={{ opacity: 0, y: 18 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, amount: 0.4 }}
            transition={{ duration: 0.5 }}
            className="bg-void p-8 md:p-10"
          >
            <span className="font-mono text-xs uppercase tracking-widest text-signal">
              What Chakravyuh is
            </span>
            <ul className="mt-6 space-y-4">
              {positioning.is.map((line) => (
                <li key={line} className="flex items-start gap-3 text-ink-1">
                  <Check size={16} className="text-signal mt-1 shrink-0" />
                  <span className="leading-relaxed">{line}</span>
                </li>
              ))}
            </ul>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 18 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, amount: 0.4 }}
            transition={{ duration: 0.5, delay: 0.1 }}
            className="bg-void p-8 md:p-10"
          >
            <span className="font-mono text-xs uppercase tracking-widest text-red">
              What Chakravyuh is not
            </span>
            <ul className="mt-6 space-y-4">
              {positioning.isNot.map((line) => (
                <li key={line} className="flex items-start gap-3 text-ink-2">
                  <X size={16} className="text-red mt-1 shrink-0" />
                  <span className="leading-relaxed">{line}</span>
                </li>
              ))}
            </ul>
          </motion.div>
        </div>

        <motion.p
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          viewport={{ once: true, amount: 0.5 }}
          transition={{ duration: 0.6 }}
          className="mt-16 font-display text-2xl md:text-3xl text-ink-1 max-w-3xl leading-snug"
        >
          A reasoning system that finds what's broken, proves it, and shows its work —
          the decision to fix it always stays with a human.
        </motion.p>
      </div>
    </section>
  );
}
