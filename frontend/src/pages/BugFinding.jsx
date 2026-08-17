import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Bug, Zap, Brain, Code2, CheckCircle, ChevronRight, Clock, ChevronDown, ChevronUp } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, ResponsiveContainer, Tooltip } from 'recharts';
import { fuzzingResults, semgrepFindings, crashes } from '../data/mockData';
import './BugFinding.css';

const anim = (d = 0) => ({
  initial: { opacity: 0, y: 12 },
  animate: { opacity: 1, y: 0 },
  transition: { duration: 0.35, delay: d }
});

const covData = [8, 22, 38, 51, 61, 65, 67, 67.4].map((v, i) => ({ t: `${i}m`, v }));

const TIMELINE = [
  { time: '14:22:01', icon: '🔍', text: 'Static findings loaded — 3 suspicious sinks identified', type: 'info' },
  { time: '14:22:02', icon: '🎯', text: 'AFLGo configured — targeting handle_request():148 & parse_header():91', type: 'info' },
  { time: '14:22:03', icon: '🧠', text: 'LLM seed generation — 14 structured seeds synthesized from AST context', type: 'info' },
  { time: '14:24:18', icon: '💥', text: 'CRASH #1 — heap-buffer-overflow WRITE 512 bytes @ src/server.c:148', type: 'crash' },
  { time: '14:24:19', icon: '✓', text: 'Crash confirmed reproducible (5/5 replays) — dispatched to PoV Verifier', type: 'success' },
  { time: '14:25:11', icon: '💥', text: 'CRASH #2 — stack-buffer-overflow WRITE 256 bytes @ src/parser.c:91', type: 'crash' },
  { time: '14:26:40', icon: '✓', text: 'Bug-finding complete — 3 unique PoVs confirmed, concolic escalation not needed', type: 'success' },
];

export default function BugFinding() {
  const [expandedCrash, setExpandedCrash] = useState('crash-001');
  const [showTimeline, setShowTimeline] = useState(false);

  return (
    <div>
      {/* Header */}
      <motion.div className="page-header" {...anim(0)}>
        <div className="page-header__eyebrow">STAGE 02 · PARALLEL DISCOVERY</div>
        <h1 className="page-header__title">Bug Finding Engine</h1>
        <p className="page-header__subtitle">
          Static Analysis + Directed Fuzzing (AFL++) + LLM Seed Synthesis running in parallel · Autonomous sink guidance
        </p>
      </motion.div>

      {/* 3 Parallel Methods (Concise Status Grid) */}
      <motion.div className="grid-3 section-gap--sm" {...anim(0.04)}>
        {[
          {
            icon: Code2, label: 'Static Analysis', engine: 'Semgrep + CodeQL', color: 'blue',
            badge: 'COMPLETE', stats: ['2,000 Rules Run', '3 Critical Sinks', '2 Taint Paths'],
          },
          {
            icon: Zap, label: 'Directed Fuzzing', engine: 'AFL++ / AFLGo', color: 'amber',
            badge: 'COMPLETE', stats: ['3.18M Executions', '12,400 Exec/sec', '3 Unique Crashes'],
          },
          {
            icon: Brain, label: 'LLM Reasoning', engine: 'DeepSeek-Coder 16B', color: 'purple',
            badge: 'COMPLETE', stats: ['5 Functions Checked', '14 Seeds Generated', '2 Triggered PoVs'],
          },
        ].map(m => {
          const Icon = m.icon;
          return (
            <div key={m.label} className={`card bf__method-card bf__method-card--${m.color}`}>
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <div className={`bf__method-icon bf__method-icon--${m.color}`}><Icon size={16} /></div>
                  <div>
                    <strong className="text-sm">{m.label}</strong>
                    <div className="text-xs text-muted">{m.engine}</div>
                  </div>
                </div>
                <span className="badge badge--green" style={{ fontSize: 9 }}>{m.badge}</span>
              </div>
              <div className="bf__method-stats">
                {m.stats.map(st => (
                  <span key={st} className="bf__stat-chip">{st}</span>
                ))}
              </div>
            </div>
          );
        })}
      </motion.div>

      {/* Confirmed Crashes Section */}
      <motion.div className="section-gap--sm" {...anim(0.08)}>
        <div className="flex items-center justify-between mb-3">
          <span className="mono text-xs font-bold text-muted uppercase tracking-wider">
            Confirmed Vulnerabilities Discovered (3 Unique)
          </span>
          <span className="text-xs text-muted">Click to toggle ASan execution traces</span>
        </div>

        <div className="stack--sm">
          {crashes.map(c => {
            const isExp = expandedCrash === c.id;
            return (
              <div key={c.id} className="card accent-left-red bf__crash-card">
                <div
                  className="flex items-center justify-between cursor-pointer flex-wrap gap-2"
                  onClick={() => setExpandedCrash(isExp ? null : c.id)}
                >
                  <div className="flex items-center gap-3">
                    <span className="badge badge--critical">{c.severity}</span>
                    <span className="badge badge--info">{c.cwe}</span>
                    <strong className="text-sm">{c.type}</strong>
                    <span className="mono text-xs text-muted">in {c.function}()</span>
                  </div>

                  <div className="flex items-center gap-4">
                    <span className="mono text-xs text-muted">{c.file}:{c.line}</span>
                    <div className="flex items-center gap-1">
                      <span className="mono text-xs font-bold text-amber">{c.confidence}%</span>
                      <span className="text-xs text-muted">conf.</span>
                    </div>
                    <button className="btn btn--ghost" style={{ padding: '2px 8px', minHeight: 'unset' }}>
                      {isExp ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                    </button>
                  </div>
                </div>

                <div className="bf__crash-summary-line mt-2">
                  <span className="mono text-xs text-red font-semibold">● {c.asanSummary}</span>
                  <span className="mono text-xs text-muted">{c.signal} (exit {c.returnCode})</span>
                </div>

                <AnimatePresence>
                  {isExp && (
                    <motion.div
                      initial={{ opacity: 0, height: 0 }}
                      animate={{ opacity: 1, height: 'auto' }}
                      exit={{ opacity: 0, height: 0 }}
                      transition={{ duration: 0.2 }}
                      style={{ marginTop: 12, paddingTop: 12, borderTop: '1px solid var(--border-1)' }}
                    >
                      <div className="terminal">
                        <div className="terminal__header">
                          <div className="terminal__dot"/><div className="terminal__dot"/><div className="terminal__dot"/>
                          <span className="terminal__label">AddressSanitizer Crash Trace · {c.id}</span>
                        </div>
                        <div className="terminal__body" style={{ maxHeight: 110, fontSize: 11.5 }}>
                          {c.stackTrace.map((frame, fi) => (
                            <div key={fi} className={fi === 1 ? 't-highlight' : 't-comment'}>
                              {'  #' + fi + ' ' + frame}
                            </div>
                          ))}
                        </div>
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            );
          })}
        </div>
      </motion.div>

      {/* Coverage & Timeline Grid */}
      <motion.div className="grid-2 section-gap--sm" {...anim(0.12)}>
        <div className="card">
          <div className="card-header" style={{ marginBottom: 10, paddingBottom: 8 }}>
            <span className="card-title"><Zap size={14} /> AFL++ Coverage Trajectory</span>
            <span className="mono text-xs text-cyan font-bold">67.4% Final</span>
          </div>
          <ResponsiveContainer width="100%" height={120}>
            <AreaChart data={covData} margin={{ top: 2, right: 4, left: -24, bottom: 0 }}>
              <defs>
                <linearGradient id="bfCov" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="var(--cyan)" stopOpacity={0.25} />
                  <stop offset="95%" stopColor="var(--cyan)" stopOpacity={0} />
                </linearGradient>
              </defs>
              <XAxis dataKey="t" tick={{ fontSize: 9, fill: 'var(--t3)', fontFamily: 'var(--font-mono)' }} axisLine={false} tickLine={false} />
              <YAxis domain={[0, 100]} tick={{ fontSize: 9, fill: 'var(--t3)', fontFamily: 'var(--font-mono)' }} axisLine={false} tickLine={false} />
              <Area type="monotone" dataKey="v" stroke="var(--cyan-light)" strokeWidth={2} fill="url(#bfCov)" dot={false} />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Collapsible Orchestrator Decision Log */}
        <div className="card">
          <div
            className="flex items-center justify-between"
            style={{ cursor: 'pointer' }}
            onClick={() => setShowTimeline(!showTimeline)}
          >
            <div className="flex items-center gap-2">
              <Clock size={14} style={{ color: 'var(--amber-light)' }} />
              <span className="card-title" style={{ fontSize: 13 }}>Orchestrator Decision Feed</span>
            </div>
            <button className="btn btn--ghost" style={{ padding: '2px 8px', minHeight: 'unset', fontSize: 11 }}>
              {showTimeline ? 'Collapse' : 'Expand (7 Events)'}
            </button>
          </div>

          <div className="bf__timeline-preview mt-3">
            {(showTimeline ? TIMELINE : TIMELINE.slice(0, 3)).map((e, idx) => (
              <div key={idx} className={`bf__feed-item bf__feed-item--${e.type}`}>
                <span className="mono text-xs text-muted" style={{ minWidth: 54 }}>{e.time}</span>
                <span className="text-xs text-secondary">{e.text}</span>
              </div>
            ))}
          </div>
        </div>
      </motion.div>
    </div>
  );
}
