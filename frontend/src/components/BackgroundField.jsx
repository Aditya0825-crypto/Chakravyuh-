import { motion, useScroll, useTransform } from "framer-motion";

export default function BackgroundField() {
  const { scrollYProgress } = useScroll();
  const rotate = useTransform(scrollYProgress, [0, 1], [0, 40]);
  const rotateSlow = useTransform(scrollYProgress, [0, 1], [0, -20]);

  return (
    <div className="fixed inset-0 -z-10 overflow-hidden bg-void">
      <div className="absolute inset-0 bg-grid opacity-60" />
      <motion.svg
        style={{ rotate }}
        className="absolute -right-[28vw] top-[8vh] w-[70vw] h-[70vw] opacity-[0.14]"
        viewBox="0 0 400 400"
        aria-hidden="true"
      >
        {[190, 150, 110, 70].map((r, i) => (
          <circle
            key={r}
            cx="200"
            cy="200"
            r={r}
            fill="none"
            stroke={i % 2 === 0 ? "#00ff9d" : "#6f9db3"}
            strokeWidth="1"
            strokeDasharray={i % 2 === 0 ? "1 10" : "6 6"}
          />
        ))}
      </motion.svg>
      <motion.svg
        style={{ rotate: rotateSlow }}
        className="absolute -left-[24vw] bottom-[4vh] w-[56vw] h-[56vw] opacity-[0.10]"
        viewBox="0 0 400 400"
        aria-hidden="true"
      >
        {[180, 130, 80].map((r, i) => (
          <circle
            key={r}
            cx="200"
            cy="200"
            r={r}
            fill="none"
            stroke="#ffb800"
            strokeWidth="1"
            strokeDasharray="2 8"
          />
        ))}
      </motion.svg>
      <div className="absolute inset-0 bg-gradient-to-b from-void via-transparent to-void" />
    </div>
  );
}
