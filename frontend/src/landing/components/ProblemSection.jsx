import { motion } from "framer-motion";
import { Eyebrow } from "./Atoms";

const points = [
  {
    n: "01",
    title: "Hidden vulnerabilities scale faster than reviewers",
    body: "Critical infrastructure codebases grow every sprint. Manual security audits can't keep pace, and coverage gaps become the default state, not the exception.",
  },
  {
    n: "02",
    title: "\"AI patching\" today means unverified guesses",
    body: "Most AI-assisted fixing tools generate plausible-looking code with no proof it actually closes the hole — or that it doesn't open a new one.",
  },
  {
    n: "03",
    title: "Defense environments can't accept a black box",
    body: "A system that patches production infrastructure without explainability, evidence, or a human decision point is not deployable in a defense context — full stop.",
  },
];

export default function ProblemSection() {
  return (
    <section id="problem" className="relative px-6 md:px-10 py-28 md:py-36">
      <div className="mx-auto max-w-[1400px]">
        <Eyebrow accent="amber">The Problem</Eyebrow>
        <motion.h2
          initial={{ opacity: 0, y: 14 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 0.5 }}
          transition={{ duration: 0.6 }}
          className="mt-5 font-display text-3xl md:text-5xl font-medium tracking-tight max-w-3xl text-ink-1"
        >
          Manual auditing doesn't scale. Unverified AI patching isn't safe. Defense
          infrastructure needs both — proven.
        </motion.h2>

        <div className="mt-16 grid md:grid-cols-3 gap-px bg-line">
          {points.map((p, i) => (
            <motion.div
              key={p.n}
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, amount: 0.4 }}
              transition={{ duration: 0.5, delay: i * 0.12 }}
              className="bg-void p-8"
            >
              <span className="font-mono text-xs text-red/80 tracking-widest">{p.n}</span>
              <h3 className="mt-4 font-display text-xl text-ink-1 leading-snug">{p.title}</h3>
              <p className="mt-3 text-ink-2 leading-relaxed">{p.body}</p>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}
