import { motion, useScroll, useSpring, useTransform } from "framer-motion";

export default function ConduitLine({ containerRef }) {
  const { scrollYProgress } = useScroll({
    target: containerRef,
    offset: ["start 20%", "end 70%"],
  });
  const smooth = useSpring(scrollYProgress, { stiffness: 60, damping: 22, mass: 0.4 });
  const nodeTop = useTransform(smooth, (v) => `${v * 100}%`);
  const nodeOpacity = useTransform(smooth, (v) => (v > 0.01 ? 1 : 0));

  return (
    <div
      className="absolute left-[26px] md:left-[38px] top-0 bottom-0 w-px -translate-x-1/2 pointer-events-none"
      aria-hidden="true"
    >
      <div className="absolute inset-0 bg-line" />
      <motion.div
        className="absolute left-0 top-0 w-px bg-gradient-to-b from-signal via-signal to-transparent origin-top"
        style={{ scaleY: smooth, height: "100%" }}
      />
      <motion.div
        className="absolute left-1/2 -translate-x-1/2 w-3 h-3 rounded-full bg-signal shadow-[0_0_18px_4px_rgba(0,255,157,0.55)]"
        style={{
          top: nodeTop,
          opacity: nodeOpacity,
        }}
      />
    </div>
  );
}
