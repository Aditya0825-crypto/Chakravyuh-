import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Dna, Database } from 'lucide-react';
import { vulnDNAResults } from '../data/mockData';
import './VulnDNA.css';

const anim = (d = 0) => ({
  initial: { opacity: 0, y: 12 },
  animate: { opacity: 1, y: 0 },
  transition: { duration: 0.35, delay: d }
});

export default function VulnDNA() {
  const [selected, setSelected] = useState(vulnDNAResults[0]);
  const [showQueryVector, setShowQueryVector] = useState(false);

  return (
    <div>
      {/* Header */}
      <motion.div className="page-header" {...anim(0)}>
        <div className="page-header__eyebrow">STAGE 04 · EVIDENCE RETRIEVAL</div>
        <h1 className="page-header__title">VulnDNA Engine</h1>
        <p className="page-header__subtitle">
          Semantic vector embeddings search 5,312 real-world CVE patches in 84ms · Zero LLM hallucination
        </p>
      </motion.div>

      {/* Core Innovation Highlights Strip */}
      <motion.div className="card card--amber section-gap--sm vdna__core-banner" {...anim(0.04)}>
        <div className="flex items-center gap-3">
          <div className="vdna__badge-icon"><Dna size={18} /></div>
          <div>
            <div className="font-bold text-amber text-sm">Evidence-Grounded Repair Synthesis</div>
            <div className="text-xs text-secondary mt-1">
              CHAKRAVYUH vectorizes the crash signature and retrieves proven production patches from real CVEs.
            </div>
          </div>
        </div>
        <div className="vdna__core-metrics">
          <div className="vdna__metric-chip">
            <span className="mono font-bold text-primary">5,312</span>
            <span className="text-xs text-muted">CVE Patches</span>
          </div>
          <div className="vdna__metric-chip">
            <span className="mono font-bold text-cyan">84 ms</span>
            <span className="text-xs text-muted">Query Time</span>
          </div>
          <div className="vdna__metric-chip">
            <span className="mono font-bold text-green">91.3%</span>
            <span className="text-xs text-muted">Top Match</span>
          </div>
        </div>
      </motion.div>

      {/* Collapsible Vector Query Fingerprint */}
      <motion.div className="card section-gap--sm" {...anim(0.08)} style={{ padding: '14px 20px' }}>
        <div
          className="flex items-center justify-between cursor-pointer"
          onClick={() => setShowQueryVector(!showQueryVector)}
        >
          <div className="flex items-center gap-2">
            <Database size={14} style={{ color: 'var(--cyan-light)' }} />
            <span className="font-semibold text-sm">Query Vector Fingerprint: crash-001</span>
            <span className="badge badge--info" style={{ fontSize: 9 }}>768-dim CPU Vector</span>
          </div>
          <button className="btn btn--ghost" style={{ padding: '2px 8px', minHeight: 'unset', fontSize: 11 }}>
            {showQueryVector ? 'Hide Fingerprint' : 'Inspect Vector'}
          </button>
        </div>

        <AnimatePresence>
          {showQueryVector && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              transition={{ duration: 0.2 }}
              style={{ marginTop: 12, paddingTop: 12, borderTop: '1px solid var(--border-1)' }}
            >
              <div className="grid-4" style={{ gap: 8 }}>
                {[
                  { k: 'Bug Class', v: 'CWE-122 Heap Overflow' },
                  { k: 'Trigger Sink', v: 'strcpy() write 512b' },
                  { k: 'Taint Source', v: 'Network TCP Buffer' },
                  { k: 'Language', v: 'C99 Linux ELF' },
                ].map(item => (
                  <div key={item.k} className="p-2 bg-panel rounded" style={{ background: 'var(--bg-panel)', padding: '6px 10px', borderRadius: 4 }}>
                    <div className="text-xs text-muted mono">{item.k}</div>
                    <div className="text-xs font-semibold text-primary">{item.v}</div>
                  </div>
                ))}
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </motion.div>

      {/* Master-Detail Retrieved CVEs */}
      <motion.div className="grid-asym section-gap--sm" {...anim(0.12)}>
        {/* Left: Ranked Match List */}
        <div className="stack--sm">
          <div className="mono text-xs font-bold text-muted uppercase">Top Retrieved Matches</div>
          {vulnDNAResults.map(ev => {
            const isSel = selected?.cveId === ev.cveId;
            return (
              <div
                key={ev.cveId}
                className={`card vdna__cve-card ${isSel ? 'vdna__cve-card--active' : ''}`}
                onClick={() => setSelected(ev)}
                style={{ padding: '12px 14px', cursor: 'pointer' }}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="mono text-xs font-bold text-amber">{ev.cveId}</span>
                  <span className="mono text-xs font-bold text-green">{ev.similarity}%</span>
                </div>
                <div className="text-xs text-primary font-medium truncate">{ev.title}</div>
                <div className="flex items-center gap-2 mt-2">
                  <span className="badge badge--info" style={{ fontSize: 9 }}>{ev.cwe}</span>
                  <span className="tag" style={{ fontSize: 9 }}>{ev.project}</span>
                </div>
              </div>
            );
          })}
        </div>

        {/* Right: Selected Match Details & Diff */}
        {selected && (
          <div className="card" style={{ padding: '20px 24px' }}>
            <div className="flex items-start justify-between gap-4 mb-4 flex-wrap">
              <div>
                <div className="flex items-center gap-2">
                  <h2 className="mono text-amber font-bold" style={{ fontSize: 18 }}>{selected.cveId}</h2>
                  <span className="badge badge--info">{selected.cwe}</span>
                  <span className="tag">{selected.project} ({selected.language})</span>
                </div>
                <p className="text-sm text-secondary mt-1">{selected.title}</p>
              </div>

              <div className="vdna__match-badge">
                <span className="mono text-green font-bold" style={{ fontSize: 22 }}>{selected.similarity}%</span>
                <span className="text-xs text-muted">SIMILARITY</span>
              </div>
            </div>

            {/* Pattern Box */}
            <div className="vdna__pattern-card mb-4">
              <div className="mono text-xs font-bold text-cyan uppercase mb-1">Extracted Fix Strategy:</div>
              <div className="text-sm text-primary font-medium">{selected.fixPattern}</div>
            </div>

            {/* Historical Patch Diff */}
            <div className="terminal">
              <div className="terminal__header">
                <div className="terminal__dot"/><div className="terminal__dot"/><div className="terminal__dot"/>
                <span className="terminal__label">Historical Production Diff · {selected.cveId} ({selected.function})</span>
              </div>
              <div className="terminal__body" style={{ maxHeight: 160, fontSize: 11.5 }}>
                {(selected.patch || '').split('\n').map((line, i) => (
                  <div key={i} className={
                    line.startsWith('+') && !line.startsWith('+++') ? 't-success' :
                    line.startsWith('-') && !line.startsWith('---') ? 't-error' :
                    line.startsWith('@@') ? 't-warning' : 't-comment'
                  }>
                    {line}
                  </div>
                ))}
              </div>
            </div>

            <div className="text-xs text-muted mt-3" style={{ lineHeight: 1.5 }}>
              <strong>Why It Works:</strong> {selected.whyItWorks}
            </div>
          </div>
        )}
      </motion.div>
    </div>
  );
}
