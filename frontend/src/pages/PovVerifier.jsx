import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { ShieldCheck, CheckCircle, ChevronDown, ChevronUp, Hash } from 'lucide-react';
import { crashes } from '../data/mockData';
import './PovVerifier.css';

const anim = (d = 0) => ({
  initial: { opacity: 0, y: 12 },
  animate: { opacity: 1, y: 0 },
  transition: { duration: 0.35, delay: d }
});

export default function PovVerifier() {
  const [expanded, setExpanded] = useState('crash-001');
  const [showDedup, setShowDedup] = useState(false);

  return (
    <div>
      {/* Header */}
      <motion.div className="page-header" {...anim(0)}>
        <div className="page-header__eyebrow">STAGE 03 · ADVERSARIAL VERIFICATION</div>
        <h1 className="page-header__title">PoV Verifier</h1>
        <p className="page-header__subtitle">
          Containerized crash replay · ASan trace normalization · Stack hash deduplication · Multi-metric confidence scoring
        </p>
      </motion.div>

      {/* 5-Step Pipeline Strip */}
      <motion.div className="card section-gap--sm" {...anim(0.04)} style={{ padding: '16px 20px' }}>
        <div className="pov__steps-bar">
          {[
            { step: '01', title: 'Container Replay', desc: '5/5 Isolated Replays' },
            { step: '02', title: 'ASan Classifier', desc: 'CWE Type Identification' },
            { step: '03', title: 'Stack Extraction', desc: 'Normalized Frame Depths' },
            { step: '04', title: 'Hash Dedup', desc: '4 Duplicates Dropped' },
            { step: '05', title: 'Confidence Math', desc: '85% Weighted Mean' },
          ].map((st, i, arr) => (
            <React.Fragment key={st.step}>
              <div className="pov__step-unit">
                <div className="flex items-center gap-1">
                  <CheckCircle size={13} style={{ color: 'var(--green-light)' }} />
                  <span className="mono text-xs font-bold text-primary">{st.step}. {st.title}</span>
                </div>
                <span className="text-xs text-muted mt-1">{st.desc}</span>
              </div>
              {i < arr.length - 1 && <span className="pov__step-arrow">→</span>}
            </React.Fragment>
          ))}
        </div>
      </motion.div>

      {/* Verified Crashes Accordion */}
      <motion.div className="section-gap--sm" {...anim(0.08)}>
        <div className="flex items-center justify-between mb-3">
          <span className="mono text-xs font-bold text-muted uppercase tracking-wider">
            Verified Unique Vulnerabilities ({crashes.length})
          </span>
          <span className="text-xs text-muted">Click to inspect stack trace & confidence factors</span>
        </div>

        <div className="stack--sm">
          {crashes.map(c => {
            const isExp = expanded === c.id;
            return (
              <div key={c.id} className="card accent-left-red" style={{ padding: '16px 20px' }}>
                <div
                  className="flex items-center justify-between cursor-pointer flex-wrap gap-2"
                  onClick={() => setExpanded(isExp ? null : c.id)}
                >
                  <div className="flex items-center gap-3">
                    <span className="badge badge--critical">{c.severity}</span>
                    <span className="badge badge--info">{c.cwe}</span>
                    <strong className="text-sm">{c.type}</strong>
                    <span className="mono text-xs text-muted">in {c.function}()</span>
                  </div>

                  <div className="flex items-center gap-4">
                    <span className="mono text-xs text-muted">{c.file}:{c.line}</span>
                    <div className="flex items-center gap-2">
                      <span className="mono text-xs font-bold text-amber">{c.confidence}%</span>
                      <div className="progress-track" style={{ width: 44 }}>
                        <div className="progress-fill progress-fill--amber" style={{ width: `${c.confidence}%` }} />
                      </div>
                    </div>
                    <button className="btn btn--ghost" style={{ padding: '2px 8px', minHeight: 'unset' }}>
                      {isExp ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                    </button>
                  </div>
                </div>

                <div className="pov__asan-line mt-2">
                  <span className="mono text-xs text-red font-semibold">● {c.asanSummary}</span>
                  <span className="mono text-xs text-muted">{c.signal} · exit {c.returnCode}</span>
                </div>

                <AnimatePresence>
                  {isExp && (
                    <motion.div
                      initial={{ opacity: 0, height: 0 }}
                      animate={{ opacity: 1, height: 'auto' }}
                      exit={{ opacity: 0, height: 0 }}
                      transition={{ duration: 0.2 }}
                      style={{ marginTop: 14, paddingTop: 14, borderTop: '1px solid var(--border-1)' }}
                    >
                      <div className="grid-2" style={{ gap: 16 }}>
                        {/* Terminal Trace */}
                        <div>
                          <div className="text-xs text-muted mono font-bold uppercase mb-2">ASan Normalized Frame Trace</div>
                          <div className="terminal">
                            <div className="terminal__body" style={{ maxHeight: 110, fontSize: 11 }}>
                              {c.stackTrace.map((frame, fi) => (
                                <div key={fi} className={fi === 1 ? 't-highlight' : 't-comment'}>
                                  {'  #' + fi + ' ' + frame}
                                </div>
                              ))}
                            </div>
                          </div>
                        </div>

                        {/* Confidence Weights */}
                        <div>
                          <div className="text-xs text-muted mono font-bold uppercase mb-2">Confidence Composition</div>
                          <div className="card card--panel" style={{ padding: 12 }}>
                            {[
                              { label: 'Static Match (Semgrep sink)', w: '30%' },
                              { label: 'Runtime ASan Confirmation', w: '40%' },
                              { label: 'Reproducibility (5/5 clean)', w: '20%' },
                              { label: 'Exploitability Primitive', w: '10%' },
                            ].map(w => (
                              <div key={w.label} className="stat-row" style={{ padding: '4px 0' }}>
                                <span className="text-xs text-muted">{w.label}</span>
                                <span className="mono text-xs font-bold text-green">{w.w}</span>
                              </div>
                            ))}
                          </div>
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

      {/* Collapsible Deduplication Ledger */}
      <motion.div className="card section-gap--sm" {...anim(0.12)}>
        <div
          className="flex items-center justify-between cursor-pointer"
          onClick={() => setShowDedup(!showDedup)}
        >
          <div className="flex items-center gap-2">
            <Hash size={14} style={{ color: 'var(--cyan-light)' }} />
            <span className="font-semibold text-sm">Stack Hash Deduplication Ledger (4 Duplicates Filtered)</span>
          </div>
          <button className="btn btn--ghost" style={{ padding: '2px 8px', minHeight: 'unset', fontSize: 11 }}>
            {showDedup ? 'Collapse' : 'Expand Ledger'}
          </button>
        </div>

        <AnimatePresence>
          {showDedup && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              transition={{ duration: 0.2 }}
              style={{ marginTop: 12, paddingTop: 12, borderTop: '1px solid var(--border-1)' }}
            >
              <div className="table-wrapper">
                <table>
                  <thead>
                    <tr>
                      <th>Crash ID</th>
                      <th>Stack Hash (MD5)</th>
                      <th>Root Correlation</th>
                      <th>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {[
                      { id: 'crash-004', hash: '0xA3F17C2D89B1', match: 'crash-001 (same top 3 frames)', act: 'Dropped' },
                      { id: 'crash-005', hash: '0xA3F17C2D89B1', match: 'crash-001 (identical signature)', act: 'Dropped' },
                      { id: 'crash-006', hash: '0xB7E24A1FC390', match: 'crash-002 (sprintf overflow)', act: 'Dropped' },
                      { id: 'crash-007', hash: '0xC9D82B3E7741', match: 'crash-002 (same call depth)', act: 'Dropped' },
                    ].map(r => (
                      <tr key={r.id}>
                        <td className="mono text-xs">{r.id}</td>
                        <td className="mono text-xs text-muted">{r.hash}</td>
                        <td className="text-xs text-secondary">{r.match}</td>
                        <td><span className="badge badge--neutral" style={{ fontSize: 9 }}>{r.act}</span></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </motion.div>
    </div>
  );
}
