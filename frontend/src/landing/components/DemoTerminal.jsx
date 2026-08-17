import { useEffect, useRef, useState } from "react";
import { motion, useInView } from "framer-motion";
import { Terminal, RotateCcw } from "lucide-react";
import { SectionHeading } from "./Atoms";
import { demoSteps } from "../data/criteria";

const typeColor = {
  cmd: "text-ink-1",
  log: "text-ink-2",
  success: "text-signal",
  warn: "text-amber",
  prompt: "text-steel",
};

export default function DemoTerminal() {
  const [visibleCount, setVisibleCount] = useState(0);
  const ref = useRef(null);
  const inView = useInView(ref, { once: false, amount: 0.5 });

  useEffect(() => {
    if (!inView) return;
    setVisibleCount(0);
    let i = 0;
    const interval = setInterval(() => {
      i += 1;
      setVisibleCount(i);
      if (i >= demoSteps.length) clearInterval(interval);
    }, 550);
    return () => clearInterval(interval);
  }, [inView]);

  const replay = () => setVisibleCount(0);

  return (
    <section id="demo" className="relative px-6 md:px-10 py-24 md:py-32">
      <div className="mx-auto max-w-[1000px]">
        <SectionHeading
          eyebrow="Live Demo Narrative"
          accent="signal"
          title="Watch the pipeline reason, end to end"
          sub="Mocked output — the same shape of trace the system produces on a real target."
        />

        <div ref={ref} className="mt-12 bg-panel-1 border border-line overflow-hidden">
          <div className="flex items-center justify-between px-5 py-3 border-b border-line bg-panel-2">
            <div className="flex items-center gap-2.5">
              <Terminal size={13} className="text-ink-3" />
              <span className="font-mono text-[11px] text-ink-3 uppercase tracking-widest">
                chakravyuh — demo session
              </span>
            </div>
            <button
              onClick={replay}
              className="flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-widest text-ink-3 hover:text-signal transition-colors"
            >
              <RotateCcw size={11} />
              Replay
            </button>
          </div>

          <div className="p-6 md:p-8 font-mono text-[13px] md:text-sm leading-relaxed min-h-[320px]">
            {demoSteps.slice(0, visibleCount).map((step) => (
              <motion.div
                key={step.id}
                initial={{ opacity: 0, y: 6 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.25 }}
                className={`${typeColor[step.type]} ${step.type === "prompt" ? "mt-3" : ""}`}
              >
                {step.text}
              </motion.div>
            ))}
            {visibleCount < demoSteps.length && (
              <motion.span
                animate={{ opacity: [1, 0, 1] }}
                transition={{ repeat: Infinity, duration: 0.9 }}
                className="inline-block w-2 h-4 bg-signal align-middle"
              />
            )}
          </div>
        </div>
      </div>
    </section>
  );
}
