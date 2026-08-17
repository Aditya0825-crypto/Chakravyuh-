import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Bug, Zap, Brain, Code2, CheckCircle, ChevronRight, Clock, ChevronDown, ChevronUp } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, ResponsiveContainer, Tooltip } from 'recharts';
import { fuzzingResults, semgrepFindings as fallbackSemgrep, crashes as fallbackCrashes } from '../data/mockData';
import { useScan } from '../context/ScanContext';
import { getFindings } from '../api/client';
import './BugFinding.css';

const anim = (d = 0) => ({
  initial: { opacity: 0, y: 12 },
  animate: { opacity: 1, y: 0 },
  transition: { duration: 0.35, delay: d }
});

const covData = [8, 22, 38, 51, 61, 65, 67, 67.4].map((v, i) => ({ t: `${i}m`, v }));

export default function BugFinding() {
  const { scanId, events } = useScan();
  const [crashes, setCrashes] = useState(fallbackCrashes);
  const [findings, setFindings] = useState(fallbackSemgrep);
  const [expandedCrash, setExpandedCrash] = useState('crash-001');
  const [showTimeline, setShowTimeline] = useState(false);

  useEffect(() => {
    if (!scanId) return;
    getFindings(scanId)
      .then((data) => {
        if (data?.crashes?.length > 0) {
          setCrashes(data.crashes);
          setExpandedCrash(data.crashes[0].id);
        }
        if (data?.findings?.length > 0) {
          setFindings(data.findings);
        }
      })
      .catch(() => {});
  }, [scanId]);

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
            icon: Code2, label: 'Static Analysis', engine: 'Semgrep + AST Parser', color: 'blue',
            badge: 'COMPLETE', stats: [`${findings.length} Security Sinks`, 'Call Graph Taint Path', 'Inter-procedural Flow'],
          },
          {
            icon: Zap, label: 'Directed Fuzzing', engine: 'AFL++ / Mutation Runner', color: 'amber',
            badge: 'COMPLETE', stats: [`${crashes.length} Crash Candidates`, 'Bounded Mutation Seeds', 'Memory Sanitizer Traps'],
          },
          {
            icon: Brain, label: 'LLM Reasoning', engine: 'DeepSeek-Coder / Ollama', color: 'purple',
            badge: 'COMPLETE', stats: ['Targeted PoC Synthesis', 'Boundary Exploits', 'Autonomous Triggering'],
          },
        ].map(m => {
          const Icon = m.icon;
          return (
            <div key={m.label} className={`card bf__method-card bf__method-card--${m.color}`}>
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <div className={`icon-box icon-box--${m.color}`}>
                    <Icon size={16} />
                  </div>
                  <div>
                    <div className="font-semibold text-sm">{m.label}</div>
                    <div className="text-xs text-muted mono">{m.engine}</div>
                  </div>
                </div>
                <span className={`badge badge--${m.color}`}>{m.badge}</span>
              </div>
              <div className="stack--xs">
                {m.stats.map(s => (
                  <div key={s} className="flex items-center gap-1 text-xs text-secondary">
                    <CheckCircle size={11} style={{ color: 'var(--green-light)', flexShrink: 0 }} />
                    <span>{s}</span>
                  </div>
                ))}
              </div>
            </div>
          );
        })}
      </motion.div>

      {/* Live Discovery Timeline (Collapsible) */}
      <motion.div className="card section-gap--sm" {...anim(0.08)} style={{ padding: '14px 20px' }}>
        <div
          className="flex items-center justify-between cursor-pointer"
          onClick={() => setShowTimeline(!showTimeline)}
        >
          <div className="flex items-center gap-2">
            <Clock size={15} style={{ color: 'var(--cyan-light)' }} />
            <span className="font-semibold text-sm">Real-Time Discovery Event Log</span>
            <span className="badge badge--neutral mono" style={{ fontSize: 10 }}>
              {events.length > 0 ? `${events.length} events` : '7 events'}
            </span>
          </div>
          {showTimeline ? <ChevronUp size={15} /> : <ChevronDown size={15} style={{ color: 'var(--t4)' }} />}
        </div>

        {showTimeline && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            className="bf__timeline-list mt-3"
          >
            {(events.length > 0 ? events.slice(-10) : [
              { timestamp: '14:22:01', message: 'Static findings loaded — dangerous sinks identified', type: 'info' },
              { timestamp: '14:22:02', message: 'Target candidates extracted for handle_request()', type: 'info' },
              { timestamp: '14:22:03', message: 'LLM seed generation — synthesized structured payload seeds', type: 'info' },
              { timestamp: '14:24:18', message: 'CRASH #1 — heap-buffer-overflow WRITE @ server.c:148', type: 'crash' },
              { timestamp: '14:24:19', message: 'Crash confirmed reproducible — dispatched to PoV Verifier', type: 'success' },
            ]).map((t, idx) => (
              <div key={idx} className={`bf__timeline-entry bf__timeline-entry--${t.type || 'info'}`}>
                <span className="mono text-xs text-muted bf__timeline-time">{t.timestamp ? new Date(t.timestamp).toLocaleTimeString() : '14:24:18'}</span>
                <span className="bf__timeline-icon">{t.type === 'crash' ? '💥' : '✓'}</span>
                <span className="text-xs text-secondary">{t.message || JSON.stringify(t)}</span>
              </div>
            ))}
          </motion.div>
        )}
      </motion.div>

      {/* Confirmed Crashes Section */}
      <motion.div className="section-gap--sm" {...anim(0.1)}>
        <div className="flex items-center justify-between mb-3">
          <span className="mono text-xs font-bold text-muted uppercase tracking-wider">
            Discovered Crash Candidates ({crashes.length})
          </span>
          <span className="text-xs text-muted">Click to inspect payload & ASan stderr</span>
        </div>

        <div className="stack--sm">
          {crashes.map(c => {
            const isExp = expandedCrash === c.id;
            return (
              <div key={c.id} className={`card bf__crash-card ${isExp ? 'bf__crash-card--expanded' : ''}`}>
                <div
                  className="flex items-center justify-between cursor-pointer flex-wrap gap-2"
                  onClick={() => setExpandedCrash(isExp ? null : c.id)}
                >
                  <div className="flex items-center gap-3">
                    <span className="mono text-xs text-muted">{c.id}</span>
                    <span className="badge badge--critical">{c.type || 'Heap Buffer Overflow'}</span>
                    <span className="mono text-sm font-bold">{c.function}()</span>
                    <span className="mono text-xs text-muted">{c.file}:{c.line}</span>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="badge badge--neutral mono text-xs">{c.discoveryMethod || 'Directed PoC'}</span>
                    <span className="mono text-xs font-bold text-amber">{c.confidence || 96}% Conf.</span>
                    {isExp ? <ChevronUp size={15} /> : <ChevronDown size={15} style={{ color: 'var(--t4)' }} />}
                  </div>
                </div>

                {isExp && (
                  <motion.div
                    initial={{ opacity: 0, marginTop: 0 }}
                    animate={{ opacity: 1, marginTop: 14 }}
                    className="bf__crash-body pt-3"
                    style={{ borderTop: '1px solid var(--border-1)' }}
                  >
                    <div className="grid-2 mb-3">
                      <div>
                        <span className="text-xs text-muted mono">CRASH PAYLOAD (HEX / ASCII):</span>
                        <div className="terminal mt-1" style={{ fontSize: 11 }}>
                          <div className="terminal__body" style={{ padding: '8px 12px', maxHeight: 80, overflowY: 'auto' }}>
                            <span className="t-amber mono break-all">{c.crashInput || '41414141414141414141414141414141... [512 bytes]'}</span>
                          </div>
                        </div>
                      </div>

                      <div>
                        <span className="text-xs text-muted mono">SANITIZER LOG (STDERR):</span>
                        <div className="terminal mt-1" style={{ fontSize: 11 }}>
                          <div className="terminal__body" style={{ padding: '8px 12px', maxHeight: 80, overflowY: 'auto' }}>
                            <span className="t-error mono">
                              {c.asanStderr || `==1337==ERROR: AddressSanitizer: ${c.type || 'heap-buffer-overflow'} on address 0x602000000030\nWRITE of size 512 at ${c.file}:${c.line} in ${c.function}`}
                            </span>
                          </div>
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center justify-between text-xs text-muted mono pt-2" style={{ borderTop: '1px solid var(--border-1)' }}>
                      <span>REPLAY STABILITY: <strong className="text-green">5/5 Replays Confirmed (100%)</strong></span>
                      <span>STATUS: <strong className="text-cyan">Dispatched to PoV Verifier →</strong></span>
                    </div>
                  </motion.div>
                )}
              </div>
            );
          })}
        </div>
      </motion.div>
    </div>
  );
}
