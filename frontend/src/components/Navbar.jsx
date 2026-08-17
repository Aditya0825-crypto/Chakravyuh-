import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { stages } from "../data/stages";

const navLinks = [
  { id: "problem", label: "Why" },
  { id: "pipeline", label: "Architecture" },
  { id: "criteria", label: "Judge Fit" },
  { id: "differentiators", label: "Edge" },
  { id: "stack", label: "Stack" },
  { id: "demo", label: "Demo" },
];

export default function Navbar() {
  const [activeStage, setActiveStage] = useState(null);
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 24);
    window.addEventListener("scroll", onScroll, { passive: true });
    onScroll();
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            const stage = stages.find((s) => s.id === entry.target.id);
            if (stage) setActiveStage(stage);
          }
        });
      },
      { rootMargin: "-45% 0px -45% 0px", threshold: 0 }
    );
    stages.forEach((s) => {
      const el = document.getElementById(s.id);
      if (el) observer.observe(el);
    });
    return () => observer.disconnect();
  }, []);

  return (
    <header
      className={`fixed top-0 inset-x-0 z-50 transition-all duration-300 ${
        scrolled ? "bg-void/85 backdrop-blur-md border-b border-line" : "bg-transparent border-b border-transparent"
      }`}
    >
      <div className="mx-auto max-w-[1400px] px-6 md:px-10 h-16 flex items-center justify-between">
        <a href="#top" className="flex items-center gap-2.5 group">
          <span className="relative w-5 h-5 flex items-center justify-center">
            <span className="absolute inset-0 rounded-full border border-signal/70 group-hover:border-signal transition-colors" />
            <span className="w-1.5 h-1.5 rounded-full bg-signal" />
          </span>
          <span className="font-display font-semibold tracking-tight text-sm text-ink-1">
            CHAKRAVYUH
          </span>
          <span className="font-mono text-[10px] text-ink-3 hidden sm:inline">v4.1</span>
        </a>

        <nav className="hidden lg:flex items-center gap-7 font-mono text-[11px] uppercase tracking-[0.18em] text-ink-2">
          {navLinks.map((l) => (
            <a key={l.id} href={`#${l.id}`} className="hover:text-signal transition-colors">
              {l.label}
            </a>
          ))}
        </nav>

        <div className="hidden md:flex items-center gap-5 font-mono text-[10px] uppercase tracking-[0.2em] text-ink-3 min-w-[160px] justify-end">
          {activeStage ? (
            <>
              <span className="text-signal">STAGE {activeStage.number}</span>
              <span className="text-ink-3">/06</span>
              <span className="text-ink-2 hidden xl:inline">— {activeStage.name}</span>
            </>
          ) : (
            <span className="text-ink-3">AI KAVACH 2026</span>
          )}
          <Link
            to="/console"
            className="text-signal border border-signal/40 px-3 py-1.5 hover:bg-signal/10 transition-colors normal-case tracking-normal font-medium"
          >
            Launch Console
          </Link>
        </div>
      </div>
    </header>
  );
}
