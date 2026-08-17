import { motion } from "framer-motion";
import { Dna, Crosshair, GitBranch, Users, Swords, FileText, Lock } from "lucide-react";
import { SectionHeading } from "./Atoms";
import { differentiators } from "../data/criteria";

const iconMap = {
  vulndna: Dna,
  targeted: Crosshair,
  concolic: GitBranch,
  multiagent: Users,
  adversarial: Swords,
  explainable: FileText,
  humangate: Lock,
};

export default function DifferentiatorGrid() {
  const featured = differentiators.find((d) => d.featured);
  const rest = differentiators.filter((d) => !d.featured);

  return (
    <section id="differentiators" className="relative px-6 md:px-10 py-24 md:py-32">
      <div className="mx-auto max-w-[1400px]">
        <SectionHeading
          eyebrow="Key Differentiators"
          accent="signal"
          title="The edge, stage by stage"
        />

        <div className="mt-14 grid lg:grid-cols-3 gap-4">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, amount: 0.3 }}
            transition={{ duration: 0.55 }}
            className="lg:col-span-2 lg:row-span-2 bg-panel-1 border border-signal/30 p-8 md:p-10 flex flex-col justify-between clip-corner"
          >
            <div>
              <span className="font-mono text-[10px] uppercase tracking-widest px-2 py-1 border border-signal/50 text-signal">
                Headline Innovation
              </span>
              <div className="mt-5 flex items-center gap-3">
                <Dna size={28} className="text-signal" strokeWidth={1.6} />
                <h3 className="font-display text-3xl md:text-4xl text-ink-1">
                  {featured.name}
                </h3>
              </div>
              <p className="mt-4 text-ink-2 text-lg leading-relaxed max-w-xl">{featured.desc}</p>
            </div>
            <div className="mt-8 flex gap-6 font-mono text-xs text-ink-3 uppercase tracking-widest">
              <span>Structural Signature</span>
              <span>+</span>
              <span>Semantic Match</span>
              <span>=</span>
              <span className="text-signal">Precedent, not guesswork</span>
            </div>
          </motion.div>

          {rest.map((d, i) => {
            const Icon = iconMap[d.id];
            return (
              <motion.div
                key={d.id}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true, amount: 0.4 }}
                transition={{ duration: 0.45, delay: 0.08 + i * 0.06 }}
                whileHover={{ y: -3 }}
                className="bg-panel-2 border border-line hover:border-steel/40 transition-colors p-6"
              >
                <Icon size={20} className="text-steel" strokeWidth={1.7} />
                <h4 className="mt-3 font-display text-base text-ink-1">{d.name}</h4>
                <p className="mt-2 text-sm text-ink-2 leading-relaxed">{d.desc}</p>
              </motion.div>
            );
          })}
        </div>
      </div>
    </section>
  );
}
