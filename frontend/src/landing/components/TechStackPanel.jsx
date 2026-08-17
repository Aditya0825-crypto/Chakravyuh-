import { motion } from "framer-motion";
import { Cpu, ShieldHalf, Database, Server } from "lucide-react";
import { SectionHeading } from "./Atoms";
import { techStack } from "../data/criteria";

const iconMap = { ai: Cpu, security: ShieldHalf, data: Database, infra: Server };

const deployFacts = [
  { label: "Deployment", value: "Single Laptop" },
  { label: "VRAM", value: "8 GB" },
  { label: "License Cost", value: "₹0" },
  { label: "Cloud Dependency", value: "None" },
];

export default function TechStackPanel() {
  return (
    <section id="stack" className="relative px-6 md:px-10 py-24 md:py-32">
      <div className="mx-auto max-w-[1400px]">
        <SectionHeading
          eyebrow="Tech Stack & Requirements"
          accent="steel"
          title="Deployable inside a defense network, today"
          sub="No cloud dependency, no exotic hardware, no licensing negotiation."
        />

        <div className="mt-14 grid md:grid-cols-2 lg:grid-cols-4 gap-4">
          {techStack.map((s, i) => {
            const Icon = iconMap[s.id];
            return (
              <motion.div
                key={s.id}
                initial={{ opacity: 0, y: 18 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true, amount: 0.4 }}
                transition={{ duration: 0.45, delay: i * 0.08 }}
                className="bg-panel-2 border border-line p-6"
              >
                <Icon size={20} className="text-steel" strokeWidth={1.7} />
                <h4 className="mt-3 font-mono text-xs uppercase tracking-widest text-ink-1">
                  {s.category}
                </h4>
                <ul className="mt-4 space-y-2">
                  {s.items.map((item) => (
                    <li key={item} className="text-sm text-ink-2 flex items-start gap-2">
                      <span className="w-1 h-1 rounded-full bg-signal mt-2 shrink-0" />
                      {item}
                    </li>
                  ))}
                </ul>
              </motion.div>
            );
          })}
        </div>

        <motion.div
          initial={{ opacity: 0, y: 18 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 0.4 }}
          transition={{ duration: 0.5 }}
          className="mt-4 bg-panel-3 border border-signal/25 px-6 md:px-10 py-8 grid sm:grid-cols-4 gap-6"
        >
          {deployFacts.map((f) => (
            <div key={f.label} className="text-center sm:text-left">
              <p className="font-mono text-[10px] uppercase tracking-widest text-ink-3">
                {f.label}
              </p>
              <p className="mt-1.5 font-display text-2xl text-signal">{f.value}</p>
            </div>
          ))}
        </motion.div>
      </div>
    </section>
  );
}
