import { motion } from "framer-motion";
import { BarChart, Bar, XAxis, YAxis, Cell, LabelList, ResponsiveContainer } from "recharts";
import { patchAgents, scoringWeights } from "../data/stages";

export default function PatchEngineViz() {
  return (
    <div className="mt-8">
      <div className="grid md:grid-cols-3 gap-4">
        {patchAgents.map((a, i) => (
          <motion.div
            key={a.id}
            initial={{ opacity: 0, y: 18 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, amount: 0.5 }}
            transition={{ duration: 0.5, delay: i * 0.1 }}
            whileHover={{ y: -4 }}
            className="bg-panel-2 border border-line hover:border-amber/40 transition-colors px-5 py-5 clip-corner"
          >
            <span className="font-mono text-[10px] uppercase tracking-widest text-amber">
              Agent {String(i + 1).padStart(2, "0")}
            </span>
            <h4 className="mt-2 font-display text-lg text-ink-1">{a.name}</h4>
            <p className="mt-2 text-sm text-ink-2 leading-relaxed">{a.approach}</p>
            <p className="mt-3 text-xs font-mono text-steel uppercase tracking-wide">{a.strength}</p>
          </motion.div>
        ))}
      </div>

      <div className="mt-4 flex justify-center">
        <svg width="2" height="32" className="text-line">
          <line x1="1" y1="0" x2="1" y2="32" stroke="currentColor" strokeDasharray="3 3" />
        </svg>
      </div>

      <motion.div
        initial={{ opacity: 0, y: 12 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true, amount: 0.5 }}
        transition={{ duration: 0.5, delay: 0.3 }}
        className="bg-panel-3 border border-line px-6 py-6 clip-corner"
      >
        <div className="flex items-center justify-between mb-4">
          <span className="font-mono text-xs uppercase tracking-widest text-ink-1">
            Patch Selector — Scoring Weights
          </span>
          <span className="font-mono text-[10px] text-ink-3 uppercase tracking-widest">
            highest score wins
          </span>
        </div>

        <div className="w-full h-[168px] -ml-2">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart
              data={scoringWeights}
              layout="vertical"
              margin={{ top: 4, right: 24, left: 4, bottom: 4 }}
              barCategoryGap={14}
            >
              <XAxis type="number" hide domain={[0, 55]} />
              <YAxis
                type="category"
                dataKey="name"
                width={100}
                tickLine={false}
                axisLine={false}
                tick={{ fill: "#9fb0a9", fontFamily: "JetBrains Mono", fontSize: 11 }}
              />
              <Bar dataKey="value" radius={0} isAnimationActive maxBarSize={16}>
                {scoringWeights.map((w) => (
                  <Cell key={w.name} fill={w.color} />
                ))}
                <LabelList
                  dataKey="value"
                  position="right"
                  formatter={(v) => `${v}%`}
                  style={{ fill: "#eaf2ee", fontFamily: "JetBrains Mono", fontSize: 11 }}
                />
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="mt-2 flex flex-wrap gap-x-6 gap-y-2">
          {scoringWeights.map((w) => (
            <div key={w.name} className="flex items-center gap-2 font-mono text-xs">
              <span className="w-2.5 h-2.5" style={{ backgroundColor: w.color }} />
              <span className="text-ink-2">{w.name}</span>
              <span className="text-ink-1">{w.value}%</span>
            </div>
          ))}
        </div>
      </motion.div>
    </div>
  );
}
